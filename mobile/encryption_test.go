package mobile

import (
	"testing"
	"io"
	"crypto/rand"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/secretbox"
)

func TestSecretboxEncrypt(t *testing.T) {
	test_string := "testdata"
	test_data := []byte(test_string)
	secret_key := "0123456789ABCDEFGHIJKLMNOPQRSTUV"

	require.Len(t, secret_key, 32)

	var secret_data [32]byte
	copy(secret_data[:], secret_key)

	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])

	require.NoError(t, err)

	encrypted := secretbox.Seal(nonce[:], test_data, &nonce, &secret_data)

	require.NotEmpty(t, encrypted)
}

func TestSecretboxDecrypt(t *testing.T) {
	test_string := "testdata"
	test_data := []byte(test_string)
	secret_key := "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	var secret_data [32]byte
	copy(secret_data[:], secret_key)

	var nonce [24]byte
	io.ReadFull(rand.Reader, nonce[:])

	encrypted := secretbox.Seal(nonce[:], test_data, &nonce, &secret_data)

	lenData := len(encrypted)

	require.True(t, lenData > 24)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])

	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secret_data)
	
	require.NotEmpty(t, decrypted)
	require.True(t, ok)
	require.Equal(t, decrypted, test_data)
}
