package deriver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha512"
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

func TestP384SumOfProducts(t *testing.T) {
	curve := curvey.P384()
	gBytes := curve.NewGeneratorPoint().ToAffineUncompressed()[1:]
	scalars := []curvey.Scalar{
		curve.NewScalar().New(1),
		curve.NewScalar().New(2),
		curve.NewScalar().New(3),
		curve.NewScalar().New(4),
	}
	data := make([]byte, 1+32+32+96*4+48*4)
	data[0] = 0x17
	copy(data[1:33], curveNameSecp384r1)
	data[64] = 4
	copy(data[65:161], gBytes)
	copy(data[161:257], gBytes)
	copy(data[257:353], gBytes)
	copy(data[353:449], gBytes)
	copy(data[449:497], scalars[0].Bytes())
	copy(data[497:545], scalars[1].Bytes())
	copy(data[545:593], scalars[2].Bytes())
	copy(data[593:641], scalars[3].Bytes())
	res, err := (&EcOperations{}).Run(data)
	require.NoError(t, err)
	require.Len(t, res, 96)
	expected := new(curvey.PointP384).Generator().Mul(new(curvey.ScalarP384).New(10)).ToAffineUncompressed()[1:]
	require.Equal(t, expected, res)
}

func TestP384EcdsaVerify(t *testing.T) {
	curve := elliptic.P384()
	sk, _ := ecdsa.GenerateKey(curve, crand.Reader)
	hasher := sha512.New384()
	_, _ = hasher.Write([]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."))
	digest := hasher.Sum(nil)
	r, s, err := ecdsa.Sign(crand.Reader, sk, digest)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.NotNil(t, s)

	var arr [48]byte

	data := make([]byte, 1+32+48+96+96)
	data[0] = 0x50
	copy(data[1:33], curveNameSecp384r1)
	copy(data[33:81], digest)
	sk.X.FillBytes(arr[:])
	copy(data[81:129], arr[:])
	sk.Y.FillBytes(arr[:])
	copy(data[129:177], arr[:])
	r.FillBytes(arr[:])
	copy(data[177:225], arr[:])
	s.FillBytes(arr[:])
	copy(data[225:273], arr[:])
	res, err := EcOperations{}.Run(data)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, res[0], byte(1))

	data, _ = hex.DecodeString("50bab1292f46afdcfc9425b529bf108e58aab39321ed5601f432ace7c5800d667cd3b5710e17da84216f1bf08079bbbbf45303baefc6ecd677910a1c33c86cb164281f0f2dcab55bbadc5e8606bdbc16b6364c8623c3accb308c67ef45742ff370f4c6230aa3f6cd157121d211cd56f00dab682e4175e05cf95b9c6db1844f2db0043da7480b7353816c72fa93eb26c4262b71f5cac11576071b77efbd3a5503c796670d51869b18517cad9e9db4eb49f4f8f12abba0c104a736e0a1ba510dc5f128f6f1795b3882f91ad18bdf8041aedd7412c7e5e5a5ab6e20e715e1ba6860addd193b786948ce321be901866ed2b354f255e1165fd78abeb3b241feeb10f9f8663b45ed0ffc06808066cd8005108dae")

	res, err = EcOperations{}.Run(data)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, res[0], byte(1))
}
