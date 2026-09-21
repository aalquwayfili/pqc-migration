package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const SigContext = "filesigner/v1"
const randomizedSigning = true

var oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

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

// https://www.rfc-editor.org/rfc/rfc9881.html#section-2
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type oneAsymmetricKey struct {
	Version    int
	Algorithm  algorithmIdentifier
	PrivateKey []byte
}
type mldsaBothForm struct {
	Seed        []byte
	ExpandedKey []byte
}

func marshalPublic(pk *mldsa44.PublicKey) ([]byte, error) {
	raw, err := pk.MarshalBinary()
	if err != nil {
		return nil, fail(exitIO, "marshalling public key: %w", err)
	}
	return marshalPublicBytes(raw)
}
func marshalPublicBytes(raw []byte) ([]byte, error) {
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: oidMLDSA44},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
}

func marshalPrivate(seed []byte, sk *mldsa44.PrivateKey) ([]byte, error) {
	expanded, err := sk.MarshalBinary()
	if err != nil {
		return nil, fail(exitIO, "marshalling private key: %w", err)
	}
	inner, err := asn1.Marshal(mldsaBothForm{Seed: seed, ExpandedKey: expanded})
	if err != nil {
		return nil, fail(exitIO, "marshalling key body: %w", err)
	}
	return asn1.Marshal(oneAsymmetricKey{
		Version:    0,
		Algorithm:  algorithmIdentifier{Algorithm: oidMLDSA44},
		PrivateKey: inner,
	})
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

func loadPublic(path string) (*mldsa44.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, fail(exitMalformed, "%s: bad SubjectPublicKeyInfo: %w", path, err)
	}
	if len(rest) != 0 {
		return nil, fail(exitMalformed, "%s: %d trailing bytes after SPKI", path, len(rest))
	}
	if !spki.Algorithm.Algorithm.Equal(oidMLDSA44) {
		return nil, fail(exitMalformed, "%s: algorithm is %v, expected ML-DSA-44 (%v)",
			path, spki.Algorithm.Algorithm, oidMLDSA44)
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return nil, fail(exitMalformed, "%s: AlgorithmIdentifier parameters must be absent for ML-DSA", path)
	}
	raw := spki.PublicKey.Bytes
	if len(raw) != mldsa44.PublicKeySize {
		return nil, fail(exitMalformed, "%s: public key is %d bytes, expected %d",
			path, len(raw), mldsa44.PublicKeySize)
	}
	if spki.PublicKey.BitLength != 8*len(raw) {
		return nil, fail(exitMalformed, "%s: public key BIT STRING is not byte-aligned (%d bits)",
			path, spki.PublicKey.BitLength)
	}
	canon, err := marshalPublicBytes(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, der) {
		return nil, fail(exitMalformed, "%s: SubjectPublicKeyInfo is not in the canonical ML-DSA-44 form", path)
	}
	var pk mldsa44.PublicKey
	if err := pk.UnmarshalBinary(raw); err != nil {
		return nil, fail(exitMalformed, "%s: %w", path, err)
	}
	return &pk, nil
}

// https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/
func loadPrivate(path string) (*mldsa44.PrivateKey, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	var oak oneAsymmetricKey
	rest, err := asn1.Unmarshal(der, &oak)
	if err != nil {
		return nil, fail(exitMalformed, "%s: bad PKCS#8: %w", path, err)
	}
	if len(rest) != 0 {
		return nil, fail(exitMalformed, "%s: %d trailing bytes after PKCS#8", path, len(rest))
	}
	if oak.Version != 0 {
		return nil, fail(exitMalformed, "%s: PKCS#8 version is %d, expected 0", path, oak.Version)
	}
	if !oak.Algorithm.Algorithm.Equal(oidMLDSA44) {
		return nil, fail(exitMalformed, "%s: algorithm is %v, expected ML-DSA-44 (%v)",
			path, oak.Algorithm.Algorithm, oidMLDSA44)
	}
	if len(oak.Algorithm.Parameters.FullBytes) != 0 {
		return nil, fail(exitMalformed, "%s: AlgorithmIdentifier parameters must be absent for ML-DSA", path)
	}
	inner := oak.PrivateKey
	// Raw keys can start with an ASN.1 tag; dispatch by length first.
	if len(inner) == mldsa44.PrivateKeySize {
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(inner); err != nil {
			return nil, fail(exitMalformed, "%s: %w", path, err)
		}
		return &sk, nil
	}
	if len(inner) > 0 && inner[0] == 0x30 {
		var both mldsaBothForm
		rest, err := asn1.Unmarshal(inner, &both)
		if err != nil {
			return nil, fail(exitMalformed, "%s: bad seed-and-expandedKey structure: %w", path, err)
		}
		if len(rest) != 0 {
			return nil, fail(exitMalformed, "%s: %d trailing bytes after the private key structure",
				path, len(rest))
		}
		if len(both.Seed) != mldsa44.SeedSize {
			return nil, fail(exitMalformed, "%s: seed is %d bytes, expected %d",
				path, len(both.Seed), mldsa44.SeedSize)
		}
		if len(both.ExpandedKey) != mldsa44.PrivateKeySize {
			return nil, fail(exitMalformed, "%s: expanded key is %d bytes, expected %d",
				path, len(both.ExpandedKey), mldsa44.PrivateKeySize)
		}
		canon, err := asn1.Marshal(mldsaBothForm{Seed: both.Seed, ExpandedKey: both.ExpandedKey})
		if err != nil {
			return nil, fail(exitIO, "%s: %w", path, err)
		}
		if !bytes.Equal(canon, inner) {
			return nil, fail(exitMalformed, "%s: seed-and-expandedKey structure is not canonical", path)
		}
		var seed [mldsa44.SeedSize]byte
		copy(seed[:], both.Seed)
		_, sk := mldsa44.NewKeyFromSeed(&seed)
		derived, err := sk.MarshalBinary()
		if err != nil {
			return nil, fail(exitIO, "%s: %w", path, err)
		}
		if subtle.ConstantTimeCompare(derived, both.ExpandedKey) != 1 {
			return nil, fail(exitMalformed,
				"%s: expanded key does not match the key derived from the seed", path)
		}
		return sk, nil
	}
	var raw []byte
	rest, err = asn1.Unmarshal(inner, &raw)
	if err != nil {
		return nil, fail(exitMalformed, "%s: private key is not a supported ML-DSA-44 encoding", path)
	}
	if len(rest) != 0 {
		return nil, fail(exitMalformed, "%s: %d trailing bytes after the expanded key", path, len(rest))
	}
	if len(raw) != mldsa44.PrivateKeySize {
		return nil, fail(exitMalformed, "%s: private key is %d bytes, expected %d",
			path, len(raw), mldsa44.PrivateKeySize)
	}
	var sk mldsa44.PrivateKey
	if err := sk.UnmarshalBinary(raw); err != nil {
		return nil, fail(exitMalformed, "%s: %w", path, err)
	}
	return &sk, nil
}

func readMessage(path string) ([]byte, error) {
	msg, err := os.ReadFile(path)
	if err != nil {
		return nil, fail(exitIO, "reading %s: %w", path, err)
	}
	return msg, nil
}

func keygen(privPath, pubPath string) error {
	var seed [mldsa44.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return fail(exitIO, "reading entropy: %w", err)
	}
	pk, sk := mldsa44.NewKeyFromSeed(&seed)

	skDER, err := marshalPrivate(seed[:], sk)
	if err != nil {
		return err
	}
	pkDER, err := marshalPublic(pk)
	if err != nil {
		return err
	}
	if err := writePEM(privPath, "PRIVATE KEY", skDER, 0o600); err != nil {
		return err
	}
	return writePEM(pubPath, "PUBLIC KEY", pkDER, 0o644)
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
	sig := make([]byte, mldsa44.SignatureSize)
	// https://github.com/cloudflare/circl/blob/v1.6.5/sign/mldsa/mldsa44/dilithium.go
	if err := mldsa44.SignTo(sk, msg, []byte(SigContext), randomizedSigning, sig); err != nil {
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
	if len(sig) != mldsa44.SignatureSize {
		return fail(exitMalformed, "signature is %d bytes, expected %d",
			len(sig), mldsa44.SignatureSize)
	}
	if !mldsa44.Verify(pk, msg, []byte(SigContext), sig) {
		return fail(exitReject, "signature verification failed")
	}
	return nil
}

func usage() error {
	return fail(exitUsage, "usage:\n"+
		"  filesigner-mldsa keygen -priv PATH -pub PATH\n"+
		"  filesigner-mldsa sign   -priv PATH -in FILE -sig PATH\n"+
		"  filesigner-mldsa verify -pub  PATH -in FILE -sig PATH")
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

	need := func(names ...string) error {
		for _, name := range names {
			if fs.Lookup(name).Value.String() == "" {
				return fail(exitUsage, "%s requires -%s", args[0], name)
			}
		}
		return nil
	}

	switch args[0] {
	case "keygen":
		if err := need("priv", "pub"); err != nil {
			return err
		}
		return keygen(*priv, *pub)
	case "sign":
		if err := need("priv", "in", "sig"); err != nil {
			return err
		}
		return sign(*priv, *in, *sig)
	case "verify":
		if err := need("pub", "in", "sig"); err != nil {
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
