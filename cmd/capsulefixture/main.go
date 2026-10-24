// capsulefixture emits public, intentionally insecure deterministic TEST material only.
// It is never linked into capsuled and is not a credential generator.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"math/big"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: capsulefixture OUTPUT.json")
	}
	d := big.NewInt(1)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	sign := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	layout := protocol.Layout{V: 1, Samples: []protocol.Sample{
		{ConstraintEM: 14, WidthEM: 13.75, HeightEM: 2.5},
		{ConstraintEM: 20, WidthEM: 19.5, HeightEM: 1.25},
		{ConstraintEM: 28, WidthEM: 24, HeightEM: 1.25},
	}}
	binding, _ := json.Marshal(protocol.Binding{V: 1, Service: "time-capsule-test", CapsuleID: "test-capsule-0123456789abcdef", SenderID: "123456789", RecipientID: "987654321", DurationS: 75, Layout: layout})
	payload, _ := json.Marshal(map[string]any{"v": 1, "text": "Hello 👩‍🚀 é שלום مرحبا", "entities": []map[string]any{{"type": "bold", "offset": 0, "length": 5}}})
	padded := make([]byte, 512)
	binary.BigEndian.PutUint32(padded, uint32(len(payload)))
	copy(padded[4:], payload)
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i)
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	combined := g.Seal(nil, nonce, padded, protocol.PayloadAAD(binding))
	ct, tag := combined[:len(combined)-16], combined[len(combined)-16:]
	p := append(append(append([]byte{}, nonce...), ct...), tag...)
	descriptor := protocol.Descriptor{V: 1, Service: "time-capsule-test", CapsuleID: "test-capsule-0123456789abcdef", SenderID: "123456789", RecipientID: "987654321", CreatedMS: 1792782000000, UnlockMS: 1792782075000, DurationS: 75, BindingSHA256: protocol.Digest(binding), PayloadSHA256: protocol.Digest(p), Layout: layout}
	desc, sig, carrier, e := protocol.Sign(sign, "test-key", descriptor)
	if e != nil {
		panic(e)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&sign.PublicKey)
	out := map[string]any{"test_only": true, "binding_b64url": protocol.Encode(binding), "descriptor_b64url": protocol.Encode(desc), "signature_der_b64url": protocol.Encode(sig), "public_key_spki_der_b64url": protocol.Encode(pub), "public_key_x963_b64url": protocol.Encode(elliptic.Marshal(elliptic.P256(), x, y)), "signing_input_b64url": protocol.Encode(protocol.SignatureInput("test-key", desc)), "payload_aad_b64url": protocol.Encode(protocol.PayloadAAD(binding)), "content_key": protocol.Encode(key), "nonce": protocol.Encode(nonce), "ciphertext": protocol.Encode(ct), "tag": protocol.Encode(tag), "padded_payload_b64url": protocol.Encode(padded), "plaintext_json_b64url": protocol.Encode(payload), "text": "Hello 👩‍🚀 é שלום مرحبا", "carrier": carrier, "kid": "test-key"}
	b, _ := json.MarshalIndent(out, "", "  ")
	if e = os.WriteFile(os.Args[1], append(b, '\n'), 0644); e != nil {
		panic(e)
	}
	fmt.Println("Wrote TEST-ONLY interoperability vector")
}
