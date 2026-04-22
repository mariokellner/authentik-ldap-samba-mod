//go:build !windows
// +build !windows

package common

import "syscall"

const SIGUSR1 = syscall.SIGUSR1
const SIGUSR2 = syscall.SIGUSR2
const LOCK_NB = syscall.LOCK_NB
const LOCK_EX = syscall.LOCK_EX
const LOCK_UN = syscall.LOCK_UN

func Kill(pid int, signum syscall.Signal) error {
	return syscall.Kill(pid, signum)
}

func Flock(fd int, how syscall.Signal) error {
	return syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)

}
