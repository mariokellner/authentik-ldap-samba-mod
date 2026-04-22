//go:build !windows
// +build !windows

package common

import "syscall"

const SIGUSR1 = syscall.SIGUSR1
