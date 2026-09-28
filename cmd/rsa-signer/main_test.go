package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateKeyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(path, "PRIVATE KEY", []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %o, want 600", info.Mode().Perm())
	}
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil || string(der) != "new" {
		t.Fatalf("replacement key: %q, %v", der, err)
	}
}

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
