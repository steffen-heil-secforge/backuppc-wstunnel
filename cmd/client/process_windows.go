//go:build windows

package main

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

var jobHandle windows.Handle

func initProcessGroup() error {
	// Create a Job Object
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	jobHandle = handle

	// Configure job to kill all processes when job is closed
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(
		handle,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	return err
}

func assignToProcessGroup(cmd *exec.Cmd) error {
	if jobHandle == 0 || cmd.Process == nil {
		return nil
	}
	// Open process handle with required access
	procHandle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(procHandle)

	return windows.AssignProcessToJobObject(jobHandle, procHandle)
}

func setupProcessGroup(cmd *exec.Cmd) {
	// Nothing needed before start on Windows
}

func killProcessGroup() {
	if jobHandle != 0 {
		windows.TerminateJobObject(jobHandle, 1)
		windows.CloseHandle(jobHandle)
		jobHandle = 0
	}
}
