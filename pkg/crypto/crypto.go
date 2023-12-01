package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"cs2390-acn/pkg/protocol"
	"io"
	"log/slog"
)

/*
AES: used to encrypt and decrypt the relay cell payload as it moves along the circuit.
*/
const (
	// Use AES-128 for encryption. Size of key should be 16 bytes.
	AESKeySize         = 16
	NonceSize          = 16
	RSABitSize         = 2048
	SHA256ChecksumSize = 32
	SHA256DigestSize   = 6
	PubKeyByteSize     = 65
)

// GenerateAESKey generates a random AES key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, AESKeySize)
	_, err := rand.Read(key)
	if err != nil {
		slog.Error("Error generating AES key:", err)
		return nil, err
	}
	slog.Debug("AES key generated successfully.", "Key = ", key)
	return key, nil
}

// GenerateRSAKeys generates a new RSA private and public key pair.
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, RSABitSize)
	if err != nil {
		slog.Error("Error generating RSA key pair:", err)
		return nil, nil, err
	}
	slog.Debug("RSA key pair generated successfully.")
	return privKey, &privKey.PublicKey, nil
}

// EncryptWithPublicKey encrypts data with a public key.
func EncryptWithPublicKey(msg []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, msg, nil)
	if err != nil {
		slog.Error("Error encrypting message with RSA public key:", err)
		return nil, err
	}
	slog.Debug("Message encrypted successfully with RSA public key.")
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with a private key.
func DecryptWithPrivateKey(ciphertext []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		slog.Error("Error decrypting message with RSA private key:", err)
		return nil, err
	}
	slog.Debug("Message decrypted successfully with RSA private key.")
	return plaintext, nil
}

// EncryptData encrypts data using AES-CTR.
// A random 128-bit nonce (Number Once) is generated.
// The nonce is a random value that is used only once with each key to introduce randomness.
// returns the concatenation of the nonce followed by the encrypted data.
func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		slog.Error("Error creating new AES cipher:", err)
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		slog.Error("Error reading nonce:", err)
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(ciphertext, data)

	slog.Debug("Data encrypted successfully.")
	return append(nonce, ciphertext...), nil
}

func EncryptWrapper(data [protocol.CellPayloadSize]byte, key []byte) ([protocol.CellPayloadSize]byte, error) {
	var encryptedData [protocol.CellPayloadSize]byte

	// Extract actual size from the last two bytes
	size := int(data[protocol.CellPayloadSize-2])<<8 + int(data[protocol.CellPayloadSize-1])

	// Encrypt only the data part
	encrypted, err := EncryptData(data[:size], key)
	if err != nil {
		return encryptedData, err
	}

	// Copy encrypted data back to array
	copy(encryptedData[:], encrypted)

	// Update size in the last two bytes
	newSize := len(encrypted)
	encryptedData[protocol.CellPayloadSize-2] = byte(newSize >> 8)
	encryptedData[protocol.CellPayloadSize-1] = byte(newSize & 0xff)

	return encryptedData, nil
}

// DecryptData decrypts data using AES-CTR.
// It first extracts the nonce and the actual encrypted data.
// Using the nonce and key, it decrypts the data using AES-CTR and returns the decrypted data.
func DecryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		slog.Error("Error creating new AES cipher:", err)
		return nil, err
	}

	if len(data) <= NonceSize {
		errMsg := "Ciphertext too short for valid nonce and data."
		slog.Error(errMsg)
		return nil, err
	}

	nonce, ciphertext := data[:NonceSize], data[NonceSize:]
	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	slog.Debug("Data encrypted successfully.")
	return plaintext, nil
}

func DecryptWrapper(data [protocol.CellPayloadSize]byte, key []byte) ([protocol.CellPayloadSize]byte, error) {
	var decryptedData [protocol.CellPayloadSize]byte

	// Extract actual size from the last two bytes
	size := int(data[protocol.CellPayloadSize-2])<<8 + int(data[protocol.CellPayloadSize-1])

	// Decrypt only the encrypted part
	decrypted, err := DecryptData(data[:size], key)
	if err != nil {
		return decryptedData, err
	}

	// Copy decrypted data back to array
	copy(decryptedData[:], decrypted)

	// Update size in the last two bytes
	newSize := len(decrypted)
	decryptedData[protocol.CellPayloadSize-2] = byte(newSize >> 8)
	decryptedData[protocol.CellPayloadSize-1] = byte(newSize & 0xff)

	return decryptedData, nil
}

/*
Diffie-Hellman:
Used during circuit construction.
The OP sends the first half of the Diffie-Hellman handshake (gx)
to an OR (onion router), which responds with the second half (gy).
They both can compute a shared secret key, gxy, without it being transmitted.
*/

func GenerateKeyPair(curve ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("Error generating ECDH key pair:", err)
		return nil, nil, err
	}
	pubKey := privKey.PublicKey()
	slog.Debug("ECDH key pair generated successfully.")
	return privKey, pubKey, nil
}

func ComputeSharedSecret(privKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey) ([]byte, error) {
	secret, err := privKey.ECDH(pubKey)
	if err != nil {
		slog.Error("Error computing shared secret:", err)
		return nil, err
	}
	slog.Debug("Shared secret computed successfully.")
	return secret, nil
}

// Can also use this for hash data to get digest? -- NO, because digest is 6 bytes, this is 32 bytes
func Hash(data []byte) [SHA256ChecksumSize]byte {
	hash := sha256.Sum256(data)
	slog.Debug("Shared data hashed successfully.")
	slog.Debug("Hashing done", "data", data, "hash", hash)
	return hash
}

// Hash computes a truncated SHA256 hash of the data and returns the first 6 bytes.
// WARNING: truncating can reduce its security, making it more susceptible to collisions
func HashDigest(data []byte) [SHA256DigestSize]byte {
	fullHash := sha256.Sum256(data)
	var shortHash [SHA256DigestSize]byte
	copy(shortHash[:], fullHash[:SHA256DigestSize])
	return shortHash
}
