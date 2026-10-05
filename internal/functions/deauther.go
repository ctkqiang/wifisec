package functions

type WifiDeauthenticatorConfiguration struct {
	Daemon bool   `json:"daemon"`
	Count  int    `json:"count"`
	MAC    string `json:"mac"`
	Scan   bool   `json:"scan"`
	Kill   bool   `json:"kill"`
}

func WifiDeauther(arguments []string) error {
	// DEauther UI

	return nil
}
