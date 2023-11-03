package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
)

// GenerateAESKey generates a random AES key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, AESKeySize)
	_, err := rand.Read(key)
	if err != nil {
		slog.Error("Error generating AES key:", err)
		return nil, err
	}
	slog.Info("AES key generated successfully.")
	slog.Debug("Key is %v", key)
	return key, nil
}

// GenerateRSAKeys generates a new RSA private and public key pair.
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, RSABitSize)
	if err != nil {
		slog.Error("Error generating RSA key pair:", err)
		return nil, nil, err
	}
	slog.Info("RSA key pair generated successfully.")
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
	slog.Debug("Plaintext: %v\nCiphertext: %v", data, ciphertext)
	return append(nonce, ciphertext...), nil
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

	slog.Debug("Data decrypted successfully.")
	slog.Debug("Plaintext: %v\nCiphertext: %v", plaintext, ciphertext)
	return plaintext, nil
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
	slog.Info("ECDH key pair generated successfully.")
	return privKey, pubKey, nil
}

func ComputeSharedSecret(privKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey) ([]byte, error) {
	secret, err := privKey.ECDH(pubKey)
	if err != nil {
		slog.Error("Error computing shared secret:", err)
		return nil, err
	}
	slog.Info("Shared secret computed successfully.")
	return secret, nil
}

// Can also use this for hash data to get digest?
func Hash(data []byte) [SHA256ChecksumSize]byte {
	hash := sha256.Sum256(data)
	slog.Debug("Shared data hashed successfully.")
	slog.Debug("Hashing done", "data", data, "hash", hash)
	return hash
}

/*
CREATE:
1. OP Generate a key pair (kinda temp public private)
2. RSA encrypt OP public key (using OR1 public key) and send to OR1
3. OR1 generates a key pair (kinda temp public private)
4. OR1 RSA decrypts OP public (using OR1 private key)
5. OR1 computes the shared secret using OP's public key and its private key with computeSharedSecret
6. OR1 will send its temp public key, it will also send a hash of shared secret
7. OP computes the shared secret using OR1's public key and its private key with computeSharedSecret
8 OP then verifies that the shared secret they came up with independently is the same by hashing its shared secret and comparing with the hash that was sent
9. All communication now happens on the shared secret (AES encryptions)


RELAY:
3. OP -> OR1 Relay c1{Extend, OR2, E(g^x2)}
	OP now wants to extend the circuit to OR2, so generates another key pair using generateKeyPair for OR2.
	x2: private key for OR2; g^x2: public key.
	OP uses hashSharedSecret on DATA to get Digest,
	uses EncryptData for Digest+LenCMD+DATA(OR2 address, OP's public key..)
	She sends an extend request to OR1 with encrypted data for OR2.

4. OR1 -> OR2 Create c2, E(g^x2)
	OR1 get the relayed message from OP and extract CMD "Extend", OR2's address(then update its mapping and circuit id),
	uses DecryptData to decrypt the encrypted public key E(g^x2),
	compare Digest and hashSharedSecret(DATA) not equal,
	OR1 forwards OP's request to OR2, relaying the g^x2.

5. (NOT NECCESSARY?) OR2 -> OR1 Created c2, g^y2, H(K2)
	OR2 generates a key pair using generateKeyPair,
	computes a shared secret using computeSharedSecret with OP's public key,
	then hashes the shared secret using hashSharedSecret.
	OR2 sends the hashed shared secret and its public key to OR1.

6. (NOT NECCESSARY?) OR2 -> OR1: Relay c1{Extended, g^y2, H(K2)}
	OR1 relays OR2's response back to OP.

7. OP -> OR1 -> OR2: Extend, OR2, E(g^x2)
	OR1 compares Digest and hashSharedSecret(DATA), not equal, forward based on mapping;
	OR2 compares, equal, get CMD...
*/