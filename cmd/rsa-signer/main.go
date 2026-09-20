package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

const rsaBits = 2048
const (
	exitOK        = 0
	exitReject    = 1
	exitUsage     = 2
	exitMalformed = 3
	exitIO        = 4
)

type codedError struct {
	code int
	err  error
}

func (e codedError) Error() string { return e.err.Error() }

func fail(code int, format string, a ...any) error {
	return codedError{code, fmt.Errorf(format, a...)}
}

func writePEM(path, label string, der []byte, perm os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
	if err := os.WriteFile(path, b, perm); err != nil {
		return fail(exitIO, "writing %s: %w", path, err)
	}
	return nil
}

func readPEM(path, label string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fail(exitIO, "reading %s: %w", path, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fail(exitMalformed, "%s: not PEM", path)
	}
	if blk.Type != label {
		return nil, fail(exitMalformed, "%s: expected PEM label %q, got %q", path, label, blk.Type)
	}
	return blk.Bytes, nil
}

func keygen(privPath, pubPath string) error {
	sk, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return fail(exitIO, "generating key: %w", err)
	}
	skDER, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return fail(exitIO, "marshalling private key: %w", err)
	}
	pkDER, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		return fail(exitIO, "marshalling public key: %w", err)
	}
	if err := writePEM(privPath, "PRIVATE KEY", skDER, 0o600); err != nil {
		return err
	}
	return writePEM(pubPath, "PUBLIC KEY", pkDER, 0o644)
}

func loadPrivate(path string) (*rsa.PrivateKey, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	any, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fail(exitMalformed, "%s: %w", path, err)
	}
	sk, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, fail(exitMalformed, "%s: not an RSA private key (%T)", path, any)
	}
	return sk, nil
}

func loadPublic(path string) (*rsa.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	any, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fail(exitMalformed, "%s: %w", path, err)
	}
	pk, ok := any.(*rsa.PublicKey)
	if !ok {
		return nil, fail(exitMalformed, "%s: not an RSA public key (%T)", path, any)
	}
	return pk, nil
}

func readMessage(path string) ([]byte, error) {
	msg, err := os.ReadFile(path)
	if err != nil {
		return nil, fail(exitIO, "reading %s: %w", path, err)
	}
	return msg, nil
}

func sign(privPath, inPath, sigPath string) error {
	sk, err := loadPrivate(privPath)
	if err != nil {
		return err
	}
	msg, err := readMessage(inPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, sk, crypto.SHA256, digest[:])
	if err != nil {
		return fail(exitIO, "signing: %w", err)
	}
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		return fail(exitIO, "writing %s: %w", sigPath, err)
	}
	return nil
}

func verify(pubPath, inPath, sigPath string) error {
	pk, err := loadPublic(pubPath)
	if err != nil {
		return err
	}
	msg, err := readMessage(inPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fail(exitIO, "reading %s: %w", sigPath, err)
	}
	if len(sig) != pk.Size() {
		return fail(exitMalformed, "signature is %d bytes, expected %d", len(sig), pk.Size())
	}
	digest := sha256.Sum256(msg)
	if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig); err != nil {
		return fail(exitReject, "signature verification failed")
	}
	return nil
}

func usage() error {
	return fail(exitUsage, "usage:\n"+
		"  filesigner-rsa keygen -priv PATH -pub PATH\n"+
		"  filesigner-rsa sign   -priv PATH -in FILE -sig PATH\n"+
		"  filesigner-rsa verify -pub  PATH -in FILE -sig PATH")
}

func run(args []string) error {
	if len(args) < 1 {
		return usage()
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	priv := fs.String("priv", "", "private key path")
	pub := fs.String("pub", "", "public key path")
	in := fs.String("in", "", "input file")
	sig := fs.String("sig", "", "signature path")
	if err := fs.Parse(args[1:]); err != nil {
		return fail(exitUsage, "%w", err)
	}

	need := func(pairs map[string]string) error {
		for name, v := range pairs {
			if v == "" {
				return fail(exitUsage, "%s requires -%s", args[0], name)
			}
		}
		return nil
	}

	switch args[0] {
	case "keygen":
		if err := need(map[string]string{"priv": *priv, "pub": *pub}); err != nil {
			return err
		}
		return keygen(*priv, *pub)
	case "sign":
		if err := need(map[string]string{"priv": *priv, "in": *in, "sig": *sig}); err != nil {
			return err
		}
		return sign(*priv, *in, *sig)
	case "verify":
		if err := need(map[string]string{"pub": *pub, "in": *in, "sig": *sig}); err != nil {
			return err
		}
		return verify(*pub, *in, *sig)
	default:
		return usage()
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var ce codedError
		if errors.As(err, &ce) {
			os.Exit(ce.code)
		}
		os.Exit(exitIO)
	}
	os.Exit(exitOK)
}
