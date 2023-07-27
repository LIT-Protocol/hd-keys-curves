package deriver

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
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
	fmt.Printf("%x", output)
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

func TestDeriver_ComputeKeyRandom(t *testing.T) {
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

func TestDeriver_ComputeKeyTestVectorsSecp256k1(t *testing.T) {
	curve := curves.K256()

	testDeriver_ComputeKeyTestVectors(
		t,
		curve,
		K256,
		[]byte("LIT_HD_KEY_ID_secp256k1_XMD:SHA-256_SSWU_RO_NUL_"),
		&testVector{
			tweaks: []curves.Scalar{
				scalarFromHex(curve, "80efe4d28a41cf962133bfcaa2807d38a7f5cec16941cc6d6eec8e76185d2a43"),
				scalarFromHex(curve, "5afd988c6086d335f892a43ccf943d3973814eadd315adc04bb12808f1c1ac4e"),
				scalarFromHex(curve, "666f2ce0352e74402c16c02df1b8c29334898e89792eb3ccea54172289c8683b"),
				scalarFromHex(curve, "d8d9ab7eb84354614b196236009e60f10f28c1c389013c53c907d203f69c9dcf"),
				scalarFromHex(curve, "8be371c633650ced7b804f127f7c657ec555abc9b9388bdaff3768089e35f1e7"),
			},
			derivedSecretKeys: []curves.Scalar{
				scalarFromHex(curve, "028b65b2be48d4995b4605fd15d9fe84a8a2aa2844413144e7fd639f02cb3cec"),
				scalarFromHex(curve, "34be9c0d1df4c55b61bf3a988387ec4cea445f0b3269ec19612f8b73adf52384"),
				scalarFromHex(curve, "5b839258a5f5865db5a18fa17ce49682f6febe4cf47d8f46c996ac85296f8d71"),
				scalarFromHex(curve, "df625948f6b7e50f1909765ec8c59e4326681cb4d46ee907e17612f964f2ba6c"),
				scalarFromHex(curve, "9dac6a026edd43d2ad6dc7ebc6ff8632a288bed21a0404c3c725a20c4d45982f"),
			},
			derivedPublicKeys: []curves.Point{
				pointFromHex(curve, "03da91c23e934cfa868670f46f8e984c6ab6b2f72177917ab30f34f842a0e26bd5"),
				pointFromHex(curve, "038a4f4d11de67b125728db83c8c8d08e62dd4c9af93d8697e3c540287c2775a74"),
				pointFromHex(curve, "028debebba9542d40dae7845fc063176dce0743bff37dca74ce452952b7ec62f55"),
				pointFromHex(curve, "038bd9b34d3be3ac6000a29d3ead1010d1017a69f85a11057bfaa6912e8f0f5fdd"),
				pointFromHex(curve, "03f57045f267f445992a0f03f6fe7f558e0196ce29f625ba729c98ee2893694ab9"),
			},
		})
}

func TestDeriver_ComputeKeyTestVectorsP256(t *testing.T) {
	curve := curves.P256()

	testDeriver_ComputeKeyTestVectors(
		t,
		curve,
		P256,
		[]byte("LIT_HD_KEY_ID_P256_XMD:SHA-256_SSWU_RO_NUL_"),
		&testVector{
			tweaks: []curves.Scalar{
				scalarFromHex(curve, "1904454890517f02460b3090aee8c7f36d6993227e6f27eaedd7adfbac0b460d"),
				scalarFromHex(curve, "1cd310c26703f8bec930666d67498f07bbbe76100802e15d2cf834bc5628ce6e"),
				scalarFromHex(curve, "4efb6fc0886164c60f6f0561f13ad53e84983b94d68748ee6ec80c51b18726c6"),
				scalarFromHex(curve, "50433e9b91006ce9ff5cab790cc2e35d5179db0e880662e9a97b2f2a3ecbde10"),
				scalarFromHex(curve, "0c221262db211cc7510a2e88b8397e3022bd92256682ab0b402ba6708ef7b9d6"),
			},
			derivedSecretKeys: []curves.Scalar{
				scalarFromHex(curve, "58fba55256985ef89dc0999ac0bbf2d05eb86be5a8b81139f8d74ade08df2bb3"),
				scalarFromHex(curve, "41e17406b223fec0ee0bc2db4be43f45ea5c93e526c84bcb87423aea130beac9"),
				scalarFromHex(curve, "8ce56baec638b8652119284f1b98ef688aa24c4f84a8be7e30d56ecb653c23f2"),
				scalarFromHex(curve, "f7eec172b9267a1d4edaa09ff9c92d04da6b1fd00eab5d3b61220467a155c827"),
				scalarFromHex(curve, "86022a1e51f487a59d3ace8b9b0da41efca0ce32cad337bea225ac8d9dde1b4c"),
			},
			derivedPublicKeys: []curves.Point{
				pointFromHex(curve, "026f51f2f553020f3800fb62dad9a5163ed1cb588d2f2d1f08361af7fed9c02404"),
				pointFromHex(curve, "0221e2d7a6cd0e4583302da5a2eb80ecff7071fc9197ed55bc184fe8c1bf3857c0"),
				pointFromHex(curve, "0335c8856a840b4d15e56950cd7b629d8a1f369df319042614daa4112037aee88c"),
				pointFromHex(curve, "03c834c78faea62bb3e764162c4bf2fe2981265b1515065a2faf25834dd5611201"),
				pointFromHex(curve, "02c997c2960435511bfdf38222ce69195aa136b809ddf33f118b7cbcae4d22b358"),
			},
		})
}

type testVector struct {
	tweaks            []curves.Scalar
	derivedSecretKeys []curves.Scalar
	derivedPublicKeys []curves.Point
}

func testDeriver_ComputeKeyTestVectors(t *testing.T, curve *curves.Curve, curveType CurveType, cxt []byte, vector *testVector) {
	rootSecretKeys := []curves.Scalar{
		createScalar(curve, []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}),
		createScalar(curve, []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}),
		createScalar(curve, []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}),
		createScalar(curve, []byte{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}),
		createScalar(curve, []byte{13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13}),
	}
	rootPublicKeys := []curves.Point{
		curve.ScalarBaseMult(rootSecretKeys[0]),
		curve.ScalarBaseMult(rootSecretKeys[1]),
		curve.ScalarBaseMult(rootSecretKeys[2]),
		curve.ScalarBaseMult(rootSecretKeys[3]),
		curve.ScalarBaseMult(rootSecretKeys[4]),
	}
	ids := [][]byte{
		[]byte(""),
		[]byte("abc"),
		[]byte("abcdef0123456789"),
		[]byte("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"),
		[]byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	for i := 0; i < 5; i++ {
		deriver, err := NewDeriver(curveType, ids[i], cxt)
		require.NoError(t, err)
		require.NotNil(t, deriver)
		require.Equal(t, deriver.value.Cmp(vector.tweaks[i]), 0)
		sk := deriver.ComputeSecretKey(rootSecretKeys)
		require.Equal(t, sk.Cmp(vector.derivedSecretKeys[i]), 0)
		pk := deriver.ComputePublicKey(rootPublicKeys)
		require.True(t, pk.Equal(vector.derivedPublicKeys[i]))
	}
}

func createScalar(curve *curves.Curve, input []byte) curves.Scalar {
	s, _ := curve.NewScalar().SetBytes(input)
	return s
}

func scalarFromHex(curve *curves.Curve, hexString string) curves.Scalar {
	s, _ := hex.DecodeString(hexString)
	return createScalar(curve, s)
}

func pointFromHex(curve *curves.Curve, hexString string) curves.Point {
	h, _ := hex.DecodeString(hexString)
	p, _ := curve.Point.FromAffineCompressed(h)
	return p
}
