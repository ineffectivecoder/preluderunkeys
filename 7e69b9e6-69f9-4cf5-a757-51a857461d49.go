//go:build windows

/*
ID: 7e69b9e6-69f9-4cf5-a757-51a857461d49
NAME: runkey
UNIT: test
CREATED: 2024-01-24 18:44:41.054965
*/
package main

import (
	"path/filepath"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

func setautorun() {
	var err error
	var k registry.Key
	Endpoint.Say("Opening registry key handle")
	k, err = registry.OpenKey(
		registry.CURRENT_USER,
		filepath.Join("Software",
			"Microsoft",
			"Windows",
			"CurrentVersion",
			"Run"),
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		Endpoint.Say(err.Error())
	}
	Endpoint.Say("Adding malicious value to run key")
	err = k.SetStringValue("SuperMaliciousRunKey", "calc.exe")
	if err != nil {
		Endpoint.Say(err.Error())
	}
	Endpoint.Say("Attempting to close registry key handle")
	if err = k.Close(); err != nil {
		Endpoint.Say(err.Error())
	}
}

func test() {
	setautorun()
	Endpoint.Stop(100)
}

func clean() {
	var err error
	var k registry.Key
	Endpoint.Say("Cleaning up")
	Endpoint.Say("Opening registry key handle")
	k, err = registry.OpenKey(
		registry.CURRENT_USER,
		filepath.Join("Software",
			"Microsoft",
			"Windows",
			"CurrentVersion",
			"Run"),
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		Endpoint.Say(err.Error())
	}
	Endpoint.Say("Removing malicious run key")
	err = k.DeleteValue("SuperMaliciousRunKey")
	if err != nil {
		Endpoint.Say(err.Error())
	}
	Endpoint.Say("Attempting to close registry key handle")
	if err = k.Close(); err != nil {
		Endpoint.Say(err.Error())
	}
}

func main() {
	Endpoint.Start(test, clean)
}
