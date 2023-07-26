package deriver

import (
	crand "crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDeriveParams_Marshaling(t *testing.T) {
	curve := curves.K256()
	secretKeys := make([]curves.Scalar, 10)
	publicKeys := make([]curves.Point, 10)
	for i := 0; i < 10; i++ {
		sk := curve.NewScalar().Random(crand.Reader)
		pk := curve.ScalarBaseMult(sk)
		secretKeys[i] = sk
		publicKeys[i] = pk
	}
	id := []byte("cait-sith-id")
	cxt := []byte("LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_")

	params := &deriveParams{
		curveType: K256,
		id:        id,
		cxt:       cxt,
		rootKeys:  publicKeys,
	}
	output, err := params.MarshalBinary()
	require.NoError(t, err)
	params2 := new(deriveParams)
	err = params2.UnmarshalBinary(output)
	require.NoError(t, err)
	require.Equal(t, params.curveType, params2.curveType)
	require.Equal(t, params.id, params2.id)
	require.Equal(t, params.cxt, params2.cxt)
	for i, pk := range params.rootKeys {
		require.True(t, pk.Equal(params2.rootKeys[i]))
	}
}

func TestDeriver_ComputeKey(t *testing.T) {
	deriver, err := NewDeriver(K256, []byte("cait-sith-id"), []byte("LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_"))
	require.NoError(t, err)
	require.NotNil(t, deriver)
	curve := curves.K256()
	secretKeys := make([]curves.Scalar, 10)
	publicKeys := make([]curves.Point, 10)
	for i := 0; i < 10; i++ {
		sk := curve.NewScalar().Random(crand.Reader)
		pk := curve.ScalarBaseMult(sk)
		secretKeys[i] = sk
		publicKeys[i] = pk
	}
	sk := deriver.ComputeSecretKey(secretKeys)
	pk := deriver.ComputePublicKey(publicKeys)

	require.True(t, pk.Equal(curve.ScalarBaseMult(sk)))
}
