package common

import (
	"os"
	"syscall"
)

const SIGUSR1 = syscall.Signal(30)
const SIGUSR2 = syscall.Signal(31)

// DIRTY, Better use https://github.com/juju/fslock
const LOCK_NB = syscall.Signal(4)
const LOCK_EX = syscall.Signal(2)
const LOCK_UN = syscall.Signal(8)

func Kill(pid int, signum syscall.Signal) error {

	if process, err := os.FindProcess(pid); err == nil {
		return process.Kill()
	}

	return nil
}

func Flock(fd int, how syscall.Signal) error {
	return nil // not implemented jet

}
