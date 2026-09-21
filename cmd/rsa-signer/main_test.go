package main

import (
	"errors"
	"strings"
	"testing"
)

func TestMissingFlags(t *testing.T) {
	for command, missing := range map[string]string{
		"keygen": "priv", "keygen -priv p": "pub",
		"sign": "priv", "sign -priv p": "in", "sign -priv p -in m": "sig",
		"verify": "pub", "verify -pub p": "in", "verify -pub p -in m": "sig",
	} {
		args := strings.Fields(command)
		for i := 0; i < 20; i++ {
			err := run(args)
			var ce codedError
			if !errors.As(err, &ce) || ce.code != exitUsage || err.Error() != args[0]+" requires -"+missing {
				t.Fatalf("%s: %v", command, err)
			}
		}
	}
}
