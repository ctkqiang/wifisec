package functions

import "wifisec/internal/security"

type WifiDeauthenticatorConfiguration struct {
	Daemon bool   `json:"daemon"`
	Count  int    `json:"count"`
	MAC    string `json:"mac"`
	Scan   bool   `json:"scan"`
	Kill   bool   `json:"kill"`
}

func WifiDeauther(arguments []string) error {
	var (
		checker security.PrivilegeChecker = security.RootChecker{}
		err                               = checker.Check()
	)

	if err != nil {
		return err
	}

	return nil
}
