// Copyright 2015 CNI authors
// Copyright 2017 rmohr@redhat.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ns

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"regexp"
	"runtime"
	"sync"
	"syscall"
)

type Namespace interface {
	// Executes the passed closure in this object's namespace,
	// attempting to restore the original namespace before returning.
	// However, since each OS thread can have a different namespace,
	// and Go's thread scheduling is highly variable, callers cannot
	// guarantee any specific namespace is set unless operations that
	// require that namespace are wrapped with Do().  Also, no code called
	// from Do() should call runtime.UnlockOSThread(), or the risk
	// of executing code in an incorrect namespace will be greater.  See
	// https://github.com/golang/go/wiki/LockOSThread for further details.
	Do(toRun func(Namespace) error) error

	// Sets the current namespace to this object's namespace.
	// Note that since Go's thread scheduling is highly variable, callers
	// cannot guarantee the requested namespace will be the current namespace
	// after this function is called; to ensure this wrap operations that
	// require the namespace with Do() instead.
	Set() error

	// Returns the filesystem path representing this object's namespace
	Path() string

	// Returns a file descriptor representing this object's namespace
	Fd() uintptr

	// Cleans up this instance of the namespace; if this instance
	// is the last user the namespace will be destroyed
	Close() error
}

type namespace struct {
	file      *os.File
	mounted   bool
	closed    bool
	nsType    int
	nsTypeStr string
}

// Returns an object representing the namespace referred to by @path
func GetNS(nspath string) (Namespace, error) {
	err := IsNSorErr(nspath)
	if err != nil {
		return nil, err
	}

	//cgroup  ipc  mnt  net  pid  user  uts
	res := regexp.MustCompile(`^/proc/[^/]+/ns/([^/]+)`).FindStringSubmatch(nspath)
	if len(res) != 2 {
		return nil, fmt.Errorf("Error detecting namespace type for path: %s", nspath)
	}

	var nsType int
	switch res[1] {
	case "pid":
		nsType = unix.CLONE_NEWPID
	case "mnt":
		nsType = unix.CLONE_NEWNS
	case "net":
		nsType = unix.CLONE_NEWNET
	default:
		return nil, fmt.Errorf("Error unsupported namespace requested: %s", res[1])
	}

	fd, err := os.Open(nspath)
	if err != nil {
		return nil, err
	}
	return namespace{file: fd, nsType: nsType, nsTypeStr: res[1]}, nil
}

func (ns *namespace) Set() error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	if _, _, err := unix.Syscall(unix.SYS_SETNS, ns.Fd(), uintptr(ns.nsType), 0); err != 0 {
		return fmt.Errorf("Error switching to ns %v: %v", ns.file.Name(), err)
	}

	return nil
}

func (ns *namespace) Close() error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	if err := ns.file.Close(); err != nil {
		return fmt.Errorf("Failed to close %q: %v", ns.file.Name(), err)
	}
	ns.closed = true

	if ns.mounted {
		if err := unix.Unmount(ns.file.Name(), unix.MNT_DETACH); err != nil {
			return fmt.Errorf("Failed to unmount namespace %s: %v", ns.file.Name(), err)
		}
		if err := os.RemoveAll(ns.file.Name()); err != nil {
			return fmt.Errorf("Failed to clean up namespace %s: %v", ns.file.Name(), err)
		}
		ns.mounted = false
	}

	return nil
}

func (ns *namespace) Path() string {
	return ns.file.Name()
}

func (ns *namespace) Fd() uintptr {
	return ns.file.Fd()
}

func (ns *namespace) errorIfClosed() error {
	if ns.closed {
		return fmt.Errorf("%q has already been closed", ns.file.Name())
	}
	return nil
}

func (ns *namespace) Do(toRun func(Namespace) error) error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	containedCall := func(hostNS Namespace) error {
		threadNS, err := GetNS(ns.getCurrentThreadNSPath())
		if err != nil {
			return fmt.Errorf("failed to open current netns: %v", err)
		}
		defer threadNS.Close()

		// switch to target namespace
		if err = ns.Set(); err != nil {
			return fmt.Errorf("error switching to ns %v: %v", ns.file.Name(), err)
		}
		defer threadNS.Set() // switch back

		return toRun(hostNS)
	}

	// save a handle to current network namespace
	hostNS, err := GetNS(ns.getCurrentThreadNSPath())
	if err != nil {
		return fmt.Errorf("Failed to open current namespace: %v", err)
	}
	defer hostNS.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	var innerError error
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		innerError = containedCall(hostNS)
	}()
	wg.Wait()

	return innerError
}

func (ns *namespace) getCurrentThreadNSPath() string {
	// /proc/self/ns/net returns the namespace of the main thread, not
	// of whatever thread this goroutine is running on.  Make sure we
	// use the thread's net namespace since the thread is switching around
	return fmt.Sprintf("/proc/%d/task/%d/ns/%s", os.Getpid(), unix.Gettid(), ns.nsTypeStr)
}

// WithNSPath executes the passed closure under the given
// namespace, restoring the original namespace afterwards.
func WithNSPath(nspath string, toRun func(Namespace) error) error {
	ns, err := GetNS(nspath)
	if err != nil {
		return err
	}
	defer ns.Close()
	return ns.Do(toRun)
}

const (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
	NSFS_MAGIC   = 0x6e736673
	PROCFS_MAGIC = 0x9fa0
)

type NSPathNotExistErr struct{ msg string }

func (e NSPathNotExistErr) Error() string { return e.msg }

type NSPathNotNSErr struct{ msg string }

func (e NSPathNotNSErr) Error() string { return e.msg }

func IsNSorErr(nspath string) error {
	stat := syscall.Statfs_t{}
	if err := syscall.Statfs(nspath, &stat); err != nil {
		if os.IsNotExist(err) {
			err = NSPathNotExistErr{msg: fmt.Sprintf("failed to Statfs %q: %v", nspath, err)}
		} else {
			err = fmt.Errorf("failed to Statfs %q: %v", nspath, err)
		}
		return err
	}

	switch stat.Type {
	case PROCFS_MAGIC, NSFS_MAGIC:
		return nil
	default:
		return NSPathNotNSErr{msg: fmt.Sprintf("unknown FS magic on %q: %x", nspath, stat.Type)}
	}
}

