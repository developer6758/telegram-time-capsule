// Package protocol defines the byte contract shared by the native iOS client and service.
package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"unicode/utf8"
)

const CarrierPrefix = "Time Capsule — requires a compatible client.\nTCAP1."
const MaxDuration int64 = 31536000

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var keyIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
var decimalID = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

func ValidID(s string) bool {
	if !decimalID.MatchString(s) {
		return false
	}
	n, e := strconv.ParseInt(s, 10, 64)
	return e == nil && n > 0
}
func ValidOpaque(s string) bool { return identifier.MatchString(s) }
func ValidKeyID(s string) bool  { return keyIdentifier.MatchString(s) }
func Encode(b []byte) string    { return base64.RawURLEncoding.EncodeToString(b) }
func Decode(s string, min, max int) ([]byte, error) {
	if len(s) > ((max+2)/3)*4 || len(s) == 0 {
		return nil, errors.New("invalid base64url length")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) < min || len(b) > max || Encode(b) != s {
		return nil, errors.New("invalid base64url")
	}
	return b, nil
}
func Digest(b []byte) string { h := sha256.Sum256(b); return Encode(h[:]) }
func RandomID() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return Encode(b)
}

type Sample struct {
	ConstraintEM float64 `json:"constraint_em"`
	WidthEM      float64 `json:"width_em"`
	HeightEM     float64 `json:"height_em"`
}
type Layout struct {
	V       int      `json:"v"`
	Samples []Sample `json:"samples"`
}

func (l Layout) Validate() error {
	if l.V != 1 || len(l.Samples) != 3 {
		return errors.New("invalid layout")
	}
	for i, s := range l.Samples {
		want := []float64{14, 20, 28}[i]
		if s.ConstraintEM != want || math.IsNaN(s.WidthEM) || math.IsInf(s.WidthEM, 0) || math.IsNaN(s.HeightEM) || math.IsInf(s.HeightEM, 0) || s.WidthEM <= 0 || s.WidthEM > want || s.HeightEM <= 0 || s.HeightEM > 512 || s.WidthEM*4 != math.Trunc(s.WidthEM*4) || s.HeightEM*4 != math.Trunc(s.HeightEM*4) {
			return errors.New("invalid sample")
		}
	}
	return nil
}

type Binding struct {
	V           int    `json:"v"`
	Service     string `json:"service"`
	CapsuleID   string `json:"capsule_id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	DurationS   int64  `json:"duration_s"`
	Layout      Layout `json:"layout"`
}
type Descriptor struct {
	V             int    `json:"v"`
	Service       string `json:"service"`
	CapsuleID     string `json:"capsule_id"`
	SenderID      string `json:"sender_id"`
	RecipientID   string `json:"recipient_id"`
	CreatedMS     int64  `json:"created_ms"`
	UnlockMS      int64  `json:"unlock_ms"`
	DurationS     int64  `json:"duration_s"`
	BindingSHA256 string `json:"binding_sha256"`
	PayloadSHA256 string `json:"payload_sha256"`
	Layout        Layout `json:"layout"`
}

func SignatureInput(kid string, descriptor []byte) []byte {
	b := []byte("TCAP-DESC-v1\x00" + kid + "\x00")
	return append(b, descriptor...)
}
func Sign(key *ecdsa.PrivateKey, kid string, d Descriptor) ([]byte, []byte, string, error) {
	b, e := json.Marshal(d)
	if e != nil {
		return nil, nil, "", e
	}
	h := sha256.Sum256(SignatureInput(kid, b))
	sig, e := ecdsa.SignASN1(rand.Reader, key, h[:])
	if e != nil {
		return nil, nil, "", e
	}
	carrier := CarrierPrefix + kid + "." + Encode(b) + "." + Encode(sig)
	if len([]rune(carrier)) > 3500 {
		return nil, nil, "", errors.New("carrier too large")
	}
	return b, sig, carrier, nil
}
func PayloadAAD(binding []byte) []byte { return append([]byte("TCAP-PAYLOAD-v1\x00"), binding...) }
func Wrap(key, content []byte, kid, id string) ([]byte, []byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, nil, e
	}
	return g.Seal(nil, nonce, content, []byte("TCAP-WRAP-v1\x00"+kid+"\x00"+id)), nonce, nil
}
func Unwrap(key, wrapped, nonce []byte, kid, id string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(nonce) != g.NonceSize() {
		return nil, errors.New("invalid wrapping nonce")
	}
	return g.Open(nil, nonce, wrapped, []byte("TCAP-WRAP-v1\x00"+kid+"\x00"+id))
}
func ValidBucket(n int) bool {
	switch n {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536:
		return true
	}
	return false
}

// StrictJSON rejects duplicate keys at every depth, invalid UTF-8, unknown fields and trailing data.
// Input is bounded by the HTTP layer before this function is called.
func StrictJSON(data []byte, v any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid utf8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := walk(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing json")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	return nil
}
func walk(d *json.Decoder, depth int) error {
	if depth > 20 {
		return errors.New("json depth")
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, e := d.Token()
			if e != nil {
				return e
			}
			k, ok := t.(string)
			if !ok || seen[k] {
				return errors.New("duplicate object key")
			}
			seen[k] = true
			if e = walk(d, depth+1); e != nil {
				return e
			}
		}
		t, e = d.Token()
		if e != nil || t != json.Delim('}') {
			return errors.New("object end")
		}
	case '[':
		for d.More() {
			if e = walk(d, depth+1); e != nil {
				return e
			}
		}
		t, e = d.Token()
		if e != nil || t != json.Delim(']') {
			return errors.New("array end")
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	return nil
}
