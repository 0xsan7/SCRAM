package resolve

import (
	"encoding/base64"
	"encoding/hex"
)

func b64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// base64ToHex re-encodes a base64 digest as lowercase hex, which is the form
// CycloneDX and SPDX both use for content hashes. Returns an error rather
// than an empty string on malformed input so a bad integrity value doesn't
// silently become a wrong hash.
func base64ToHex(b64 string) (string, error) {
	raw, err := b64Decode(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
