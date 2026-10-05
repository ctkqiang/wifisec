package model

type AccessPoint struct {
	BSSID string `json:"bssid"`
	SSID  string `json:"ssid"`
}

type Scanner struct {
	AccessPoints map[string]AccessPoint `json:"access_points"`
}
