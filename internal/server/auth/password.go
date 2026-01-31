package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2 parameters (OWASP recommended values for interactive logins)
	argon2Time      = 2         // Number of iterations
	argon2Memory    = 64 * 1024 // 64 MB
	argon2Threads   = 4         // Number of threads
	argon2KeyLength = 32        // 32 bytes = 256 bits
	saltLength      = 16        // 16 bytes = 128 bits
)

// HashPassword hashes a plaintext password using Argon2id
// Returns a string in the format: $argon2id$v=19$m=65536,t=2,p=4$<base64-salt>$<base64-hash>
func HashPassword(password string) (string, error) {
	// Generate a cryptographically secure random salt
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate the hash
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLength)

	// Encode salt and hash to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return in PHC string format (Password Hashing Competition)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads, b64Salt, b64Hash), nil
}

// VerifyPassword verifies a plaintext password against a hash
func VerifyPassword(password, hashedPassword string) (bool, error) {
	// Parse the hash to extract parameters, salt, and hash
	var memory, time uint32
	var threads uint8
	var salt, hash string

	_, err := fmt.Sscanf(hashedPassword, "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		&memory, &time, &threads, &salt, &hash)
	if err != nil {
		return false, fmt.Errorf("invalid hash format: %w", err)
	}

	// Decode salt and hash from base64
	decodedSalt, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Hash the input password with the extracted parameters
	computedHash := argon2.IDKey([]byte(password), decodedSalt, time, memory, threads, uint32(len(decodedHash)))

	// Constant-time comparison to prevent timing attacks
	if len(computedHash) != len(decodedHash) {
		return false, nil
	}

	var diff byte
	for i := 0; i < len(computedHash); i++ {
		diff |= computedHash[i] ^ decodedHash[i]
	}

	return diff == 0, nil
}

// IsPasswordHashed checks if a password string is already hashed
// This is useful for migration from plaintext passwords
func IsPasswordHashed(password string) bool {
	var memory, time uint32
	var threads uint8
	var salt, hash string

	_, err := fmt.Sscanf(password, "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		&memory, &time, &threads, &salt, &hash)
	return err == nil
}
