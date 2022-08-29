package mobile

import (
	"io"
	"fmt"
	"crypto/rand"
	"golang.org/x/crypto/nacl/secretbox"
)


type EncryptionError struct {
	code int

	// 1 => Invalid SecretKey
	// 2 => Random Generator Error
	// 3 => Invalid encrypted data length
	// 4 => Decryption error
}

func (e *EncryptionError) Error() string {
    return fmt.Sprintf("%d", e.code)
}

func Encrypt(data []byte, sk []byte) ([]byte, error)  {
	var secretKey [32]byte

	if len(sk) != len(secretKey) {
		return nil, &EncryptionError{1}
	}

	copy(secretKey[:], sk)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, &EncryptionError{2}
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, &secretKey)

	return encrypted, nil
}

func Decrypt(data []byte, sk []byte) ([]byte, error) {
	var secretKey [32]byte

	if len(sk) != len(secretKey) {
		return nil, &EncryptionError{1}
	}

	copy(secretKey[:], sk)

	if len(data) < 24 {
		return nil, &EncryptionError{3}
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], data[:24])

	decrypted, ok := secretbox.Open(nil, data[24:], &decryptNonce, &secretKey)
	if !ok {
		return nil, &EncryptionError{4}
	}

	return decrypted, nil
}