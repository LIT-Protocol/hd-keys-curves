package deriver

import (
	"encoding/hex"
	"github.com/mikelodder7/curvey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEcMultiply_Run(t *testing.T) {
	input := make([]byte, 32+64+32)
	copy(input[:32], curveNamePrime256v1)
	copy(input[32:96], new(curvey.PointP256).Generator().ToAffineUncompressed()[1:])
	copy(input[96:], new(curvey.ScalarP256).New(25).Bytes())
	res, err := (&EcMultiply{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 64)
	require.Equal(t, new(curvey.PointP256).Generator().Mul(new(curvey.ScalarP256).New(25)).ToAffineUncompressed()[1:], res)
}

func TestEcAdd_Run(t *testing.T) {
	input := make([]byte, 32+128)
	copy(input[:32], curveNameCurve25519)
	copy(input[64:96], new(curvey.PointEd25519).Generator().Mul(new(curvey.ScalarEd25519).New(5)).ToAffineCompressed())
	copy(input[128:], new(curvey.PointEd25519).Generator().Mul(new(curvey.ScalarEd25519).New(15)).ToAffineCompressed())
	res, err := (&EcAdd{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 64)
	expected := new(curvey.PointEd25519).Generator().Mul(new(curvey.ScalarEd25519).New(20)).ToAffineCompressed()
	require.Equal(t, expected, res[32:])
}

func TestEcNeg_Run(t *testing.T) {
	input := make([]byte, 32+192)
	copy(input[:32], curveNameBls12381g2)
	copy(input[32:], new(curvey.PointBls12381G2).Generator().Mul(new(curvey.ScalarBls12381).New(-5)).ToAffineUncompressed())
	res, err := (&EcNeg{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 192)
	expected := new(curvey.PointBls12381G2).Generator().Mul(new(curvey.ScalarBls12381).New(5)).ToAffineUncompressed()
	require.Equal(t, expected, res)
}

func TestEcEqual_Run(t *testing.T) {
	input := make([]byte, 32+192)
	copy(input[:32], curveNameBls12381g1)
	copy(input[32:32+96], new(curvey.PointBls12381G1).Generator().ToAffineUncompressed())
	copy(input[32+96:32+96+96], new(curvey.PointBls12381G1).Generator().ToAffineUncompressed())
	res, err := (&EcEqual{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, res, []byte{1})
	copy(input[32+96:32+96+96], new(curvey.PointBls12381G1).Generator().Double().ToAffineUncompressed())
	res, err = (&EcEqual{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, res, []byte{0})
}

func TestEcIsInfinity_Run(t *testing.T) {
	input := make([]byte, 32+64)
	copy(input[:32], curveNameCurve25519)
	copy(input[64:], new(curvey.PointEd25519).Generator().ToAffineCompressed())
	res, err := (&EcIsInfinity{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, res, []byte{0})
	copy(input[64:], new(curvey.PointEd25519).Identity().ToAffineCompressed())
	res, err = (&EcIsInfinity{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, res, []byte{1})
}

func TestEcPairing_Run(t *testing.T) {
	input := make([]byte, 352)
	copy(input[:32], curveNameBls12381g1)
	input[63] = 1
	copy(input[64:160], new(curvey.PointBls12381G1).Generator().Mul(new(curvey.ScalarBls12381).New(200)).ToAffineUncompressed())
	copy(input[160:352], new(curvey.PointBls12381G2).Generator().Mul(new(curvey.ScalarBls12381).New(2)).ToAffineUncompressed())
	res, err := (&EcPairing{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 576)
	g1 := new(curvey.PointBls12381G1).Generator().Mul(new(curvey.ScalarBls12381).New(400)).(*curvey.PointBls12381G1)
	g2 := new(curvey.PointBls12381G2).Generator().(*curvey.PointBls12381G2)
	expected := g1.Pairing(g2)
	require.Equal(t, expected.Bytes(), res)
}

func TestEcSumOfProducts_Run(t *testing.T) {
	input := make([]byte, 32+32+64*3+scalarSize*3)
	copy(input[:32], curveNameSecp256k1)
	input[63] = 3
	copy(input[64:128], new(curvey.PointK256).Generator().ToAffineUncompressed()[1:])
	copy(input[128:192], new(curvey.PointK256).Generator().ToAffineUncompressed()[1:])
	copy(input[192:256], new(curvey.PointK256).Generator().ToAffineUncompressed()[1:])
	copy(input[256:288], new(curvey.ScalarK256).New(3).Bytes())
	copy(input[288:320], new(curvey.ScalarK256).New(3).Bytes())
	copy(input[320:352], new(curvey.ScalarK256).New(4).Bytes())
	res, err := (&EcSumOfProducts{}).Run(input)
	require.NoError(t, err)
	require.Len(t, res, 64)
	expected := new(curvey.PointK256).Generator().Mul(new(curvey.ScalarK256).New(10)).ToAffineUncompressed()[1:]
	require.Equal(t, expected, res)
}

func TestEcOperations_Run(t *testing.T) {
	data, err := hex.DecodeString("519d896cca2aef856a7c114e8cfea5a60344ec48ed1a3c7de7e10cc6e74581626de708a97909afe58d51c7df8ba2e4aaa1e99a74ebf0d30ad8a0a20ed5c11d65543d0db0be5d5b8fa2fcaec7c3057a4484c382a2241a944ed3f373400745732cd8073ef502c533f00c028b48d052c03248ed2f5a5cc5e91f24a14c904f3439d72bccafeccd6d820f289edaf48188047e550f2207bc6e1d533845e509884177414c4415bff1ec947b0075e284c7dcf96944da2df8e5686aacdbfe8de141d1af46b30a7d138092b198c014ea9717e884c003105e48dfaf8d09889677eca5d388f306afd5b027b66914b6034cba9f193784c1048321ff6d19f85722c5f47c90758ec8f38ca867f49a479ed383b42abdf289aa023d6af1183c61a9a07e248b75cfc3461294483c05620ff204e437513dbbb84ffacad6941d36b7801f3862d8619070ce")
	assert.NoError(t, err)
	res, err := EcOperations{}.Run(data)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, res[0], byte(1))
}
