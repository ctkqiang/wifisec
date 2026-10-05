package security

import (
	"errors"
	"os"
)

type PrivilegeChecker interface {
	Check() error
}

type RootChecker struct{}

func IsRoot() bool {
	return os.Geteuid() == 0
}

func (r RootChecker) Check() error {
	if !IsRoot() {
		return errors.New("权限不足->需要root权限")
	}

	return nil
}
