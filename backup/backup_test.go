package backup

import (
	"testing"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndRecovery(t *testing.T) {
	key := GeneratePrivateKey()
	cipher := GenerateCipherKey("Algorand export 1.0", key)
	mnemonic, err := FromKey(key)
	require.NoError(t, err)
	recoveredKey, err := ToKey(mnemonic)
	cipher2 := GenerateCipherKey("Algorand export 1.0", recoveredKey)
	require.NoError(t, err)
	require.Equal(t, recoveredKey, key)
	require.Equal(t, cipher, cipher2)
}