package scan

import (
	"io/ioutil"
	"net/http"
)

// https://gist.github.com/ankanch/8c8ec5aaf374039504946e7e2b2cdf7f

// WhatsMyIP attempts to obtain the external ip through public api
func WhatsMyIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(ip), nil
}
