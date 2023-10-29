package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log/slog"
)

/*
AES: used to encrypt and decrypt the relay cell payload as it moves along the circuit.
*/
const (
	// Use AES-128 for encryption. Size of key should be 16 bytes.
	AESKeySize = 16
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
	return key, nil
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

	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		slog.Error("Error reading nonce:", err)
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(ciphertext, data)

	slog.Info("Data encrypted successfully.")
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

	if len(data) <= 16 {
		errMsg := "Ciphertext too short for valid nonce and data."
		slog.Error(errMsg)
		return nil, err
	}

	nonce, ciphertext := data[:16], data[16:]
	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	slog.Info("Data decrypted successfully.")
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
func HashSharedSecret(secret []byte) []byte {
	hash := sha256.Sum256(secret)
	slog.Info("Shared secret hashed successfully.")
	return hash[:]
}

/*
CREATE:
1. Create c1, E(g^x1)(might use the EncryptData function to encrypt her public key, but per discussion its not neccessary?)
    OP wants to establish a connection to OR1 (Onion Router 1).
	She generates a key pair using generateKeyPair. x1: private key; g^x1: public key.
	OP sends public key to OR1
2. (NOT NECCESSARY?) Created c1, g^y1, H(K1)
	OR1 might use DecryptData to decrypt the received encrypted public key E(g^x1)
    OR1 generates its own key pair using generateKeyPair, y1: private key and g^y1: public key.
	OR1 computes the shared secret using OP's public key and its private key with computeSharedSecret.
	OR1 then hashes the shared secret using hashSharedSecret to get H(K1) and sends it back to OP.

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