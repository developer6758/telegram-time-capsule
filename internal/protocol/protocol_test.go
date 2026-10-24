package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStrictJSONBoundaries(t *testing.T) {
	for _, s := range []string{`{"a":1,"a":2}`, `{"a":{"z":1,"z":2}}`, `{"a":1} {}`, `{"a":1,"unknown":2}`, "{\"a\":\"\xff\"}", strings.Repeat("[", 22) + strings.Repeat("]", 22)} {
		var v struct {
			A any `json:"a"`
		}
		if StrictJSON([]byte(s), &v) == nil {
			t.Fatalf("accepted malformed structure")
		}
	}
	var v struct {
		A string `json:"a"`
	}
	if e := StrictJSON([]byte(`{"a":"שלום 👩‍🚀 é"}`), &v); e != nil {
		t.Fatal(e)
	}
}
func TestExactIdentifiersAndBase64(t *testing.T) {
	for _, s := range []string{"0", "01", "+1", "1.0", "9223372036854775808", "١٢٣"} {
		if ValidID(s) {
			t.Fatal("invalid id accepted")
		}
	}
	if !ValidID("9223372036854775807") {
		t.Fatal("max id rejected")
	}
	for _, s := range []string{"Zg==", "Zh", "Zg\n", "+g"} {
		if _, e := Decode(s, 1, 3); e == nil {
			t.Fatal("noncanonical base64 accepted")
		}
	}
}
func TestWrappingIdentityAndTamper(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	content := make([]byte, 32)
	rand.Read(content)
	wrapped, n, e := Wrap(key, content, "w1", "capsule1")
	if e != nil {
		t.Fatal(e)
	}
	got, e := Unwrap(key, wrapped, n, "w1", "capsule1")
	if e != nil || !bytes.Equal(got, content) {
		t.Fatal("roundtrip failed")
	}
	for _, change := range []string{"id", "kid", "nonce", "wrapped", "key"} {
		k, w, nn := append([]byte{}, key...), append([]byte{}, wrapped...), append([]byte{}, n...)
		kid, id := "w1", "capsule1"
		switch change {
		case "id":
			id = "capsule2"
		case "kid":
			kid = "w2"
		case "nonce":
			nn[0] ^= 1
		case "wrapped":
			w[0] ^= 1
		case "key":
			k[0] ^= 1
		}
		if _, e = Unwrap(k, w, nn, kid, id); e == nil {
			t.Fatalf("accepted %s mutation", change)
		}
	}
}
func TestDescriptorSignatureBindsExactBytes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := Descriptor{V: 1, Service: "test"}
	b, sig, _, e := Sign(key, "kid", d)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(SignatureInput("kid", b))
	if !ecdsa.VerifyASN1(&key.PublicKey, h[:], sig) {
		t.Fatal("verify failed")
	}
	for _, input := range [][]byte{SignatureInput("other", b), SignatureInput("kid", append(b, ' '))} {
		h = sha256.Sum256(input)
		if ecdsa.VerifyASN1(&key.PublicKey, h[:], sig) {
			t.Fatal("mutation accepted")
		}
	}
}
func TestInteropFixture(t *testing.T) {
	b, e := os.ReadFile("../../testdata/ios-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	decode := func(k string) []byte {
		v, e := Decode(m[k].(string), 1, 65536)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	pub, e := x509.ParsePKIXPublicKey(decode("public_key_spki_der_b64url"))
	if e != nil {
		t.Fatal(e)
	}
	desc, sig := decode("descriptor_b64url"), decode("signature_der_b64url")
	input := SignatureInput(m["kid"].(string), desc)
	if !bytes.Equal(input, decode("signing_input_b64url")) {
		t.Fatal("signature byte mismatch")
	}
	h := sha256.Sum256(input)
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), h[:], sig) {
		t.Fatal("fixture signature failed")
	}
	key, nonce, ct, tag, binding := decode("content_key"), decode("nonce"), decode("ciphertext"), decode("tag"), decode("binding_b64url")
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	plain, e := g.Open(nil, nonce, append(append([]byte{}, ct...), tag...), PayloadAAD(binding))
	if e != nil {
		t.Fatal(e)
	}
	n := int(binary.BigEndian.Uint32(plain))
	if n > len(plain)-4 || !bytes.Equal(plain[4:4+n], decode("plaintext_json_b64url")) {
		t.Fatal("payload differs")
	}
	var payload struct {
		V        int               `json:"v"`
		Text     string            `json:"text"`
		Entities []json.RawMessage `json:"entities"`
	}
	if StrictJSON(plain[4:4+n], &payload) != nil || payload.Text != m["text"] {
		t.Fatal("Unicode payload differs")
	}
	var descriptor Descriptor
	if StrictJSON(desc, &descriptor) != nil || descriptor.BindingSHA256 != Digest(binding) || descriptor.PayloadSHA256 != Digest(append(append(append([]byte{}, nonce...), ct...), tag...)) {
		t.Fatal("signed digest mismatch")
	}
	for _, part := range []string{"key", "nonce", "ciphertext", "tag", "binding"} {
		k, nn, c, tt, bb := append([]byte{}, key...), append([]byte{}, nonce...), append([]byte{}, ct...), append([]byte{}, tag...), append([]byte{}, binding...)
		switch part {
		case "key":
			k[0] ^= 1
		case "nonce":
			nn[0] ^= 1
		case "ciphertext":
			c[0] ^= 1
		case "tag":
			tt[0] ^= 1
		case "binding":
			bb[0] ^= 1
		}
		block, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(block)
		if _, e := g.Open(nil, nn, append(c, tt...), PayloadAAD(bb)); e == nil {
			t.Fatal("tampered fixture authenticated")
		}
	}
}
func TestLayoutRejectsInvalidGeometry(t *testing.T) {
	valid := Layout{V: 1, Samples: []Sample{{14, 8, 1.25}, {20, 8, 1.25}, {28, 8, 1.25}}}
	if valid.Validate() != nil {
		t.Fatal("valid layout")
	}
	for _, sample := range []Sample{{14, -1, 1}, {14, 15, 1}, {14, 8, 513}, {14, 8.1, 1}, {20, 8, 1}} {
		invalid := valid
		invalid.Samples = append([]Sample{}, valid.Samples...)
		invalid.Samples[0] = sample
		if invalid.Validate() == nil {
			t.Fatal("invalid geometry")
		}
	}
}

func FuzzStrictJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"v":1}`, `{"v":1,"v":2}`, `[]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 100000 {
			t.Skip()
		}
		var v Binding
		_ = StrictJSON(b, &v)
	})
}
