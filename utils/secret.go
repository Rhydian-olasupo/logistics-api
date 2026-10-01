package utils

import "os"

// JWTSecret returns the key used to sign and verify JWTs.
//
// FIX: handlers and middleware each kept their own copy of the secret, read only
// from "session_secret", while the README documents JWT_SECRET.
func JWTSecret() []byte {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte(os.Getenv("session_secret"))
}
