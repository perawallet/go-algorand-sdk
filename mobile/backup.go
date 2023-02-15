package mobile

import (
	"github.com/algorand/go-algorand-sdk/v2/backup"
)

// GenerateBackupPrivateKey creates a 16-byte random key 
func GenerateBackupPrivateKey() ([]byte) {
	return backup.GeneratePrivateKey()
}

// GenerateBackupCipherKey converts a 16-byte key into a 32-byte key 
// using provided key through HMAC:SHA256 algorithm. 
func GenerateBackupCipherKey(key string, input []byte) ([]byte) {
	return backup.GenerateCipherKey(key, input)
}

// BackupMnemonicFromKey converts a 16-byte key into a 12 word mnemonic. The generated
// mnemonic includes a checksum. Each word in the mnemonic represents 11 bits
// of data, and the last 11 bits are reserved for the checksum.
func BackupMnemonicFromKey(key []byte) (string, error) {
	return backup.FromKey(key)
}

// BackupMnemonicToKey converts a mnemonic generated using this library into the
// source key used to create it. It returns an error if the passed mnemonic has
// an incorrect checksum, if the number of words is unexpected, or if one of the
// passed words is not found in the words list.
func BackupMnemonicToKey(mnemonicStr string) ([]byte, error) {
	return backup.ToKey(mnemonicStr)
}