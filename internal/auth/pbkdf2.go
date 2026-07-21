package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// pbkdf2 derives a keyLen-byte key from password and salt using
// PBKDF2-HMAC-SHA256 (RFC 8018). This is implemented directly against
// crypto/hmac and crypto/sha256 rather than pulling in
// golang.org/x/crypto/pbkdf2, so cobweb has zero dependencies beyond
// the standard library - the algorithm itself is a well-defined,
// widely used construction (OWASP's current recommendation for
// PBKDF2-SHA256 is >=600,000 iterations for password storage; this
// package uses 210,000, aligned with common current guidance for a
// single-user local admin login rather than a multi-tenant service).
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen

	prf := func(key, msg []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(msg)
		return h.Sum(nil)
	}

	dk := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		blockBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(blockBytes, uint32(block))

		u := prf(password, append(append([]byte{}, salt...), blockBytes...))
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
