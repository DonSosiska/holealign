package rulesfeed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// SigAlg is the only signature algorithm.
const SigAlg = "ed25519"

// Sig is the detached signature of a tarball (rules-<seq>.tar.gz.sig, and the "sig" member of
// latest.json). Sig is base64(ed25519.Sign(priv, sha256(tarball))).
type Sig struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

// Pointer is latest.json, the small file servers poll.
type Pointer struct {
	Seq    uint64 `json:"seq"`
	URL    string `json:"url"` // relative to latest.json, or absolute
	SHA256 string `json:"sha256"`
	Sig    Sig    `json:"sig"`
}

// GenerateKey creates a new signing key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// KeyID is the first 16 hex characters of sha256(public key).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:16]
}

// EncodePublicKey is the base64 form used in the configuration.
func EncodePublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// ParsePublicKey decodes a base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("public key is not base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// ParsePublicKeys decodes a list of base64 public keys.
func ParsePublicKeys(in []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for i, s := range in {
		k, err := ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i+1, err)
		}
		out = append(out, k)
	}
	return out, nil
}

// WritePrivateKey stores the private key (base64 of the 32-byte seed) with mode 0600. It refuses
// to overwrite an existing file.
func WritePrivateKey(path string, priv ed25519.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite a key", path)
		}
		return err
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	return nil
}

// ReadPrivateKey reads a key written by WritePrivateKey (a 32-byte seed or a 64-byte key).
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: not base64: %w", path, err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("%s: unexpected key length %d", path, len(b))
}

// Sign signs sha256(tarball).
func Sign(priv ed25519.PrivateKey, tarball []byte) Sig {
	d := sha256.Sum256(tarball)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return Sig{Alg: SigAlg, KeyID: KeyID(pub), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, d[:]))}
}

// VerifySig checks sig over tarball against the trusted keys: the algorithm must be ed25519, the
// key_id must name one of the trusted keys, and the signature must verify with that key.
func VerifySig(tarball []byte, sig Sig, trusted []ed25519.PublicKey) error {
	if sig.Alg != SigAlg {
		return fmt.Errorf("unsupported signature algorithm %q", sig.Alg)
	}
	if len(trusted) == 0 {
		return errors.New("no trusted keys configured")
	}
	var key ed25519.PublicKey
	for _, k := range trusted {
		if KeyID(k) == sig.KeyID {
			key = k
			break
		}
	}
	if key == nil {
		return fmt.Errorf("signature key %q is not a trusted key", sig.KeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("malformed signature")
	}
	d := sha256.Sum256(tarball)
	if !ed25519.Verify(key, d[:], raw) {
		return errors.New("signature does not match the bundle")
	}
	return nil
}

// MakePointer builds latest.json content for a signed tarball.
func MakePointer(seq uint64, url string, tarball []byte, sig Sig) Pointer {
	return Pointer{Seq: seq, URL: url, SHA256: sha256Hex(tarball), Sig: sig}
}

// MarshalJSONFile renders v as indented JSON with a trailing newline.
func MarshalJSONFile(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
