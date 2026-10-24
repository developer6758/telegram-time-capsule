#!/usr/bin/env python3
"""Independent OpenSSL-backed verification of the Go/iOS wire fixture. No live credentials."""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encoded_digest(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def main():
    fixture = json.loads((Path(__file__).resolve().parents[1] / "testdata/ios-v1.json").read_text())
    assert fixture["test_only"] is True
    descriptor_bytes = decode(fixture["descriptor_b64url"])
    descriptor = json.loads(descriptor_bytes)
    binding = decode(fixture["binding_b64url"])
    public_key = serialization.load_der_public_key(decode(fixture["public_key_spki_der_b64url"]))
    assert isinstance(public_key.curve, ec.SECP256R1)
    signing_input = b"TCAP-DESC-v1\0" + fixture["kid"].encode() + b"\0" + descriptor_bytes
    assert signing_input == decode(fixture["signing_input_b64url"])
    signature = decode(fixture["signature_der_b64url"])
    public_key.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
    nonce, ciphertext, tag = (decode(fixture[key]) for key in ("nonce", "ciphertext", "tag"))
    aad = b"TCAP-PAYLOAD-v1\0" + binding
    key = decode(fixture["content_key"])
    assert (len(key), len(nonce), len(tag)) == (32, 12, 16)
    assert aad == decode(fixture["payload_aad_b64url"])
    assert descriptor["binding_sha256"] == encoded_digest(binding)
    assert descriptor["payload_sha256"] == encoded_digest(nonce + ciphertext + tag)
    binding_object = json.loads(binding)
    for field in ("v", "service", "capsule_id", "sender_id", "recipient_id", "duration_s", "layout"):
        assert descriptor[field] == binding_object[field]
    assert descriptor["unlock_ms"] == descriptor["created_ms"] + descriptor["duration_s"] * 1000
    padded = AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    assert padded == decode(fixture["padded_payload_b64url"])
    length = int.from_bytes(padded[:4], "big")
    payload_json = padded[4:4 + length]
    assert payload_json == decode(fixture["plaintext_json_b64url"])
    assert json.loads(payload_json)["text"] == fixture["text"]
    assert AESGCM(key).encrypt(nonce, padded, aad) == ciphertext + tag
    for offset in (0, len(signing_input) // 2, len(signing_input) - 1):
        tampered = bytearray(signing_input)
        tampered[offset] ^= 1
        try:
            public_key.verify(signature, bytes(tampered), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            pass
        else:
            raise AssertionError("tampered descriptor accepted")
    rejected = 0
    for field in ("key", "nonce", "ciphertext", "tag", "aad"):
        original = {"key": key, "nonce": nonce, "ciphertext": ciphertext, "tag": tag, "aad": aad}
        for offset in (0, len(original[field]) // 2, len(original[field]) - 1):
            mutated = bytearray(original[field])
            mutated[offset] ^= 1
            original[field] = bytes(mutated)
            try:
                AESGCM(original["key"]).decrypt(original["nonce"], original["ciphertext"] + original["tag"], original["aad"])
            except InvalidTag:
                rejected += 1
            else:
                raise AssertionError("tampered payload accepted")
    print(f"PASS: signature, exact bytes, binding, Unicode payload and deterministic AEAD; 3 signature + {rejected} AEAD tamper cases rejected")


if __name__ == "__main__":
    main()
