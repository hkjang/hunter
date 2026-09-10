package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func digest(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func (a *App) encrypt(s string) (string, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return "enc:v1:" + base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(s), []byte("hunter:v1"))), nil
}
func (a *App) decrypt(s string) (string, error) {
	if len(s) < 7 || s[:7] != "enc:v1:" {
		return "", fmt.Errorf("invalid ciphertext")
	}
	data, err := base64.StdEncoding.DecodeString(s[7:])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < g.NonceSize() {
		return "", fmt.Errorf("invalid ciphertext")
	}
	p, err := g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], []byte("hunter:v1"))
	return string(p), err
}
