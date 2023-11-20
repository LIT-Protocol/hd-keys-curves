package deriver

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/mikelodder7/curvey"
	"github.com/mikelodder7/curvey/native"
	"github.com/mikelodder7/curvey/native/bls12381"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/big"
)

var (
	curveNameSecp256k1 = []byte{56, 59, 39, 83, 33, 83, 243, 83, 250, 76, 198, 137, 35, 159, 115, 101, 223, 233, 36, 235, 207,
		103, 128, 126, 182, 145, 99, 7, 164, 226, 112, 30}
	curveNamePrime256v1 = []byte{236, 151, 14, 250, 71, 58, 162, 250, 152, 240, 56, 58, 218, 26, 64, 52, 15, 149, 88, 58, 236,
		119, 101, 93, 71, 74, 121, 18, 49, 68, 120, 167}
	curveNameCurve25519 = []byte{95, 235, 190, 179, 75, 175, 72, 27, 200, 83, 4, 244, 249, 232, 242, 193, 145, 139, 223, 192,
		16, 239, 86, 182, 149, 122, 201, 43, 169, 112, 141, 196}
	curveNameBls12381g1 = []byte{157, 137, 108, 202, 42, 239, 133, 106, 124, 17, 78, 140, 254, 165, 166, 3, 68, 236, 72, 237,
		26, 60, 125, 231, 225, 12, 198, 231, 69, 129, 98, 109}
	curveNameBls12381g2 = []byte{234, 117, 92, 131, 99, 84, 34, 238, 113, 135, 28, 154, 84, 213, 205, 6, 52, 142, 9, 84, 93, 98,
		145, 179, 160, 123, 115, 254, 95, 105, 154, 249}
	curveNameBls12381gt = []byte{72, 104, 114, 249, 247, 74, 129, 138, 239, 93, 192, 105, 87, 88, 22, 147, 201, 72, 247, 204,
		168, 110, 248, 13, 211, 195, 253, 59, 152, 53, 40, 135}
	hashNameSha2_256 = []byte{231, 8, 169, 121, 9, 175, 229, 141, 81, 199, 223, 139, 162, 228, 170, 161, 233, 154, 116, 235,
		240, 211, 10, 216, 160, 162, 14, 213, 193, 29, 101, 84}
	hashNameSha2_384 = []byte{165, 231, 169, 152, 179, 76, 168, 208, 185, 190, 244, 4, 230, 133, 69, 8, 117, 4, 239, 14, 186,
		60, 224, 171, 107, 45, 169, 141, 56, 53, 132, 218}
	hashNameSha2_512 = []byte{108, 235, 120, 129, 121, 66, 58, 97, 47, 240, 51, 176, 106, 220, 211, 45, 31, 41, 13, 229, 190,
		86, 186, 224, 216, 251, 42, 59, 12, 137, 61, 187}
	hashNameSha3_256 = []byte{95, 185, 33, 85, 116, 164, 111, 26, 144, 41, 228, 98, 213, 136, 12, 218, 137, 103, 7, 6, 108,
		31, 75, 243, 13, 131, 136, 147, 145, 17, 191, 204}
	hashNameSha3_384 = []byte{109, 242, 159, 237, 211, 254, 58, 205, 67, 35, 215, 64, 115, 228, 107, 173, 74, 204, 7, 118,
		106, 22, 62, 188, 20, 44, 200, 203, 243, 1, 21, 100}
	hashNameSha3_512 = []byte{20, 64, 42, 213, 151, 220, 133, 115, 38, 130, 119, 163, 202, 176, 151, 54, 38, 167, 226, 26,
		193, 245, 177, 151, 249, 38, 251, 239, 42, 144, 199, 74}
	hashNameShake128 = []byte{82, 242, 139, 107, 140, 215, 88, 250, 189, 215, 74, 41, 202, 221, 102, 126, 152, 31, 74, 226,
		45, 64, 52, 33, 130, 102, 134, 86, 232, 127, 190, 59}
	hashNameShake256 = []byte{28, 128, 198, 113, 20, 210, 141, 235, 57, 106, 193, 29, 195, 23, 49, 25, 252, 247, 70, 234, 53,
		165, 151, 207, 109, 213, 180, 102, 191, 72, 169, 159}
	hashNameKeccak256 = []byte{7, 183, 43, 66, 46, 159, 31, 22, 175, 173, 79, 183, 247, 18, 28, 221, 255, 124, 31, 87, 161,
		229, 168, 198, 233, 193, 67, 1, 4, 63, 81, 56}
	hashNameTapRoot = []byte{8, 215, 83, 31, 179, 38, 223, 4, 226, 165, 107, 122, 113, 187, 97, 125, 54, 221, 210, 133, 184,
		114, 109, 3, 149, 156, 81, 26, 98, 162, 91, 241}
)

const scalarSize = 32

func parseCurve(input []byte) (processor curveHandler, err error) {
	curve := input[:32]
	if bytes.Compare(curve, curveNameSecp256k1) == 0 {
		processor = new(k256Processor)
	} else if bytes.Compare(curve, curveNamePrime256v1) == 0 {
		processor = new(p256Processor)
	} else if bytes.Compare(curve, curveNameCurve25519) == 0 {
		processor = new(curve25519Processor)
	} else if bytes.Compare(curve, curveNameBls12381g1) == 0 {
		processor = new(bls12381g1Processor)
	} else if bytes.Compare(curve, curveNameBls12381g2) == 0 {
		processor = new(bls12381g2Processor)
	} else if bytes.Compare(curve, curveNameBls12381gt) == 0 {
		processor = new(bls12381gtProcessor)
	} else {
		err = fmt.Errorf("invalid curve")
	}
	return processor, err
}

func parseHash(input []byte) (hasher schnorrChallenge, err error) {
	name := input[:32]
	if bytes.Compare(name, hashNameSha2_256) == 0 {
		hasher = schnorrDigest{hasher: sha256.New()}
	} else if bytes.Compare(name, hashNameSha2_384) == 0 {
		hasher = schnorrDigest{hasher: sha512.New384()}
	} else if bytes.Compare(name, hashNameSha2_512) == 0 {
		hasher = schnorrDigest{hasher: sha512.New()}
	} else if bytes.Compare(name, hashNameSha3_256) == 0 {
		hasher = schnorrDigest{hasher: sha3.New256()}
	} else if bytes.Compare(name, hashNameSha3_384) == 0 {
		hasher = schnorrDigest{hasher: sha3.New384()}
	} else if bytes.Compare(name, hashNameSha3_512) == 0 {
		hasher = schnorrDigest{hasher: sha3.New512()}
	} else if bytes.Compare(name, hashNameKeccak256) == 0 {
		hasher = schnorrDigest{hasher: sha3.NewLegacyKeccak256()}
	} else if bytes.Compare(name, hashNameShake128) == 0 {
		hasher = schnorrDigest{hasher: sha3.NewShake128()}
	} else if bytes.Compare(name, hashNameShake256) == 0 {
		hasher = schnorrDigest{hasher: sha3.NewShake256()}
	} else if bytes.Compare(name, hashNameTapRoot) == 0 {
		hasher = schnorrTapRoot{}
	} else {
		err = fmt.Errorf("invalid hash")
	}
	return hasher, err
}

func inScalar(curve *curvey.Curve, input []byte, count int) ([]curvey.Scalar, error) {
	if len(input) < 32*count {
		return nil, fmt.Errorf("invalid length")
	}
	scalars := make([]curvey.Scalar, count)
	for i := 0; i < count; i++ {
		s, err := curve.NewScalar().SetBytes(input[32*i : 32*(i+1)])
		if err != nil {
			return nil, err
		}
		scalars[i] = s
	}
	return scalars, nil
}

type curveHandler interface {
	InPoint(input []byte, count int) (int, []curvey.Point, error)
	InScalar(input []byte, count int) ([]curvey.Scalar, error)
	OutPoint(point curvey.Point) []byte
	PointSize() int
	Curve() *curvey.Curve
	SchnorrPoint(point curvey.Point) []byte
	SchnorrPointSize() int
	BlsVerify(msg, input []byte) error
}

type k256Processor struct{}

func (*k256Processor) InPoint(input []byte, count int) (int, []curvey.Point, error) {
	var buf [65]byte
	if len(input) < 64*count {
		return 0, nil, fmt.Errorf("invalid length")
	}
	buf[0] = 4
	points := make([]curvey.Point, count)
	curve := curvey.K256()
	for i := 0; i < count; i++ {
		copy(buf[1:], input[64*i:64*(i+1)])
		pt, err := curve.NewIdentityPoint().FromAffineUncompressed(buf[:])
		if err != nil {
			return 0, nil, err
		}
		points[i] = pt
	}
	return 64 * count, points, nil
}

func (*k256Processor) InScalar(input []byte, count int) ([]curvey.Scalar, error) {
	return inScalar(curvey.K256(), input, count)
}

func (*k256Processor) OutPoint(point curvey.Point) []byte {
	if point == nil {
		return []byte{}
	}
	return point.ToAffineUncompressed()[1:]
}

func (*k256Processor) PointSize() int {
	return 64
}

func (*k256Processor) Curve() *curvey.Curve {
	return curvey.K256()
}

func (*k256Processor) SchnorrPoint(point curvey.Point) []byte {
	return point.ToAffineCompressed()[1:]
}

func (*k256Processor) SchnorrPointSize() int {
	return 32
}

func (*k256Processor) BlsVerify(msg, input []byte) error {
	return fmt.Errorf("not supported")
}

type p256Processor struct{}

func (*p256Processor) InPoint(input []byte, count int) (int, []curvey.Point, error) {
	var buf [65]byte
	if len(input) < 64*count {
		return 0, nil, fmt.Errorf("invalid length")
	}
	buf[0] = 4
	points := make([]curvey.Point, count)
	curve := curvey.P256()
	for i := 0; i < count; i++ {
		copy(buf[1:], input[64*i:64*(i+1)])
		pt, err := curve.NewIdentityPoint().FromAffineUncompressed(buf[:])
		if err != nil {
			return 0, nil, err
		}
		points[i] = pt
	}
	return 64 * count, points, nil
}

func (*p256Processor) InScalar(input []byte, count int) ([]curvey.Scalar, error) {
	return inScalar(curvey.P256(), input, count)
}

func (*p256Processor) OutPoint(point curvey.Point) []byte {
	if point == nil {
		return []byte{}
	}
	return point.ToAffineUncompressed()[1:]
}

func (*p256Processor) PointSize() int {
	return 64
}

func (*p256Processor) Curve() *curvey.Curve {
	return curvey.P256()
}

func (*p256Processor) SchnorrPoint(point curvey.Point) []byte {
	return point.ToAffineCompressed()[1:]
}

func (*p256Processor) SchnorrPointSize() int {
	return 32
}

func (*p256Processor) BlsVerify(msg, input []byte) error {
	return fmt.Errorf("not supported")
}

type curve25519Processor struct{}

func (*curve25519Processor) InPoint(input []byte, count int) (int, []curvey.Point, error) {
	if len(input) < 64*count {
		return 0, nil, fmt.Errorf("invalid length")
	}
	curve := curvey.ED25519()
	points := make([]curvey.Point, count)
	for i := 0; i < count; i++ {
		pt, err := curve.NewIdentityPoint().FromAffineCompressed(input[64*i+32 : 64*(i+1)])
		if err != nil {
			return 0, nil, err
		}
		points[i] = pt
	}
	return 64 * count, points, nil
}

func (*curve25519Processor) InScalar(input []byte, count int) ([]curvey.Scalar, error) {
	return inScalar(curvey.ED25519(), input, count)
}

func (*curve25519Processor) OutPoint(point curvey.Point) []byte {
	if point == nil {
		return []byte{}
	}
	var buf [64]byte
	copy(buf[32:], point.ToAffineCompressed())
	return buf[:]
}

func (*curve25519Processor) PointSize() int {
	return 64
}

func (*curve25519Processor) Curve() *curvey.Curve {
	return curvey.ED25519()
}

func (*curve25519Processor) SchnorrPoint(point curvey.Point) []byte {
	return point.ToAffineCompressed()
}

func (*curve25519Processor) SchnorrPointSize() int {
	return 32
}

func (*curve25519Processor) BlsVerify(msg, input []byte) error {
	return fmt.Errorf("not supported")
}

type bls12381g1Processor struct{}

func (*bls12381g1Processor) InPoint(input []byte, count int) (int, []curvey.Point, error) {
	if len(input) < 96*count {
		return 0, nil, fmt.Errorf("invalid length")
	}
	curve := curvey.BLS12381G1()
	points := make([]curvey.Point, count)
	for i := 0; i < count; i++ {
		pt, err := curve.NewIdentityPoint().FromAffineUncompressed(input[96*i : 96*(i+1)])
		if err != nil {
			return 0, nil, err
		}
		points[i] = pt
	}
	return 96 * count, points, nil
}

func (*bls12381g1Processor) InScalar(input []byte, count int) ([]curvey.Scalar, error) {
	return inScalar(curvey.BLS12381G1(), input, count)
}

func (*bls12381g1Processor) OutPoint(point curvey.Point) []byte {
	if point == nil {
		return []byte{}
	}
	return point.ToAffineUncompressed()
}

func (*bls12381g1Processor) PointSize() int {
	return 96
}

func (*bls12381g1Processor) Curve() *curvey.Curve {
	return curvey.BLS12381G1()
}

func (*bls12381g1Processor) SchnorrPoint(point curvey.Point) []byte {
	return point.ToAffineCompressed()
}

func (*bls12381g1Processor) SchnorrPointSize() int {
	return 48
}

func (p *bls12381g1Processor) BlsVerify(msg, input []byte) error {
	if len(input) < 96+192 {
		return fmt.Errorf("invalid length")
	}
	pt1, err := new(curvey.PointBls12381G1).FromAffineUncompressed(input[:96])
	if err != nil {
		return err
	}
	if pt1.IsIdentity() || !pt1.IsOnCurve() {
		return fmt.Errorf("invalid public key")
	}
	pk := pt1.(*curvey.PointBls12381G1)
	pt2, err := new(curvey.PointBls12381G2).FromAffineUncompressed(input[96 : 96+192])
	if err != nil {
		return err
	}
	if pt2.IsIdentity() || !pt2.IsOnCurve() {
		return fmt.Errorf("invalid signature")
	}
	sig := pt2.(*curvey.PointBls12381G2)
	engine := new(bls12381.Engine)

	p2 := new(bls12381.G2).Hash(native.EllipticPointHasherSha256(), msg, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"))
	engine.AddPair(pk.Value, p2)
	engine.AddPairInvG1(new(bls12381.G1).Generator(), sig.Value)
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("invalid signature")
	}
}

type bls12381g2Processor struct{}

func (*bls12381g2Processor) InPoint(input []byte, count int) (int, []curvey.Point, error) {
	if len(input) < 192*count {
		return 0, nil, fmt.Errorf("invalid length")
	}
	curve := curvey.BLS12381G2()
	points := make([]curvey.Point, count)
	for i := 0; i < count; i++ {
		pt, err := curve.NewIdentityPoint().FromAffineUncompressed(input[192*i : 192*(i+1)])
		if err != nil {
			return 0, nil, err
		}
		points[i] = pt
	}
	return 192 * count, points, nil
}

func (*bls12381g2Processor) InScalar(input []byte, count int) ([]curvey.Scalar, error) {
	return inScalar(curvey.BLS12381G2(), input, count)
}

func (*bls12381g2Processor) OutPoint(point curvey.Point) []byte {
	if point == nil {
		return []byte{}
	}
	return point.ToAffineUncompressed()
}

func (*bls12381g2Processor) PointSize() int {
	return 192
}

func (*bls12381g2Processor) Curve() *curvey.Curve {
	return curvey.BLS12381G2()
}

func (*bls12381g2Processor) SchnorrPoint(point curvey.Point) []byte {
	return point.ToAffineCompressed()
}

func (*bls12381g2Processor) SchnorrPointSize() int {
	return 96
}

func (*bls12381g2Processor) BlsVerify(msg, input []byte) error {
	if len(input) < 96+192 {
		return fmt.Errorf("invalid length")
	}
	pt1, err := new(curvey.PointBls12381G2).FromAffineUncompressed(input[:192])
	if err != nil {
		return err
	}
	if pt1.IsIdentity() || !pt1.IsOnCurve() {
		return fmt.Errorf("invalid public key")
	}
	pk := pt1.(*curvey.PointBls12381G2)
	pt2, err := new(curvey.PointBls12381G1).FromAffineUncompressed(input[192 : 192+96])
	if err != nil {
		return err
	}
	if pt2.IsIdentity() || !pt2.IsOnCurve() {
		return fmt.Errorf("invalid signature")
	}
	sig := pt2.(*curvey.PointBls12381G1)
	engine := new(bls12381.Engine)

	p2 := new(bls12381.G1).Hash(native.EllipticPointHasherSha256(), msg, []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"))
	engine.AddPairInvG1(p2, pk.Value)
	engine.AddPair(sig.Value, new(bls12381.G2).Generator())
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("invalid signature")
	}
}

type bls12381gtProcessor struct{}

func (*bls12381gtProcessor) InPoint(input []byte, count int) (int, []curvey.Point, error) {
	if len(input) < 576*count {
		return 0, nil, fmt.Errorf("invalid length")
	}
	points := make([]curvey.Point, count)
	for i := 0; i < count; i++ {
		pt, err := new(curvey.PointBls12381Gt).FromAffineUncompressed(input[576*i : 576*(i+1)])
		if err != nil {
			return 0, nil, err
		}
		points[i] = pt
	}
	return 576 * count, points, nil
}

func (*bls12381gtProcessor) InScalar(input []byte, count int) ([]curvey.Scalar, error) {
	return inScalar(curvey.BLS12381G2(), input, count)
}

func (*bls12381gtProcessor) OutPoint(point curvey.Point) []byte {
	if point == nil {
		return []byte{}
	}
	return point.ToAffineUncompressed()
}

func (*bls12381gtProcessor) PointSize() int {
	return 576
}

func (*bls12381gtProcessor) Curve() *curvey.Curve {
	return curvey.BLS12381G2()
}

func (*bls12381gtProcessor) SchnorrPoint(point curvey.Point) []byte {
	return point.ToAffineCompressed()
}

func (*bls12381gtProcessor) SchnorrPointSize() int {
	return 576
}

func (*bls12381gtProcessor) BlsVerify(msg, input []byte) error {
	return fmt.Errorf("not supported")
}

func executeCommand(ops EcOps, input []byte) (res []byte, err error) {
	var processor curveHandler
	var e error
	i := 0
	for l := len(input); i < l; i++ {
		processor, e = parseCurve(input[i:])
		if e == nil {
			break
		}
	}
	if len(input[i+32:]) < ops.MinLength(processor) {
		return nil, fmt.Errorf("invalid length")
	}
	return ops.Handle(processor, input[i+32:])
}

type schnorrChallenge interface {
	computeChallenge(r, pubKey, msg []byte) []byte
}

type schnorrTapRoot struct{}
type schnorrDigest struct {
	hasher hash.Hash
}

func (schnorrTapRoot) computeChallenge(r, pubKey, msg []byte) []byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("BIP0340/challenge"))
	tag := hasher.Sum(nil)
	hasher.Reset()
	_, _ = hasher.Write(tag[:])
	_, _ = hasher.Write(tag[:])
	_, _ = hasher.Write(r)
	_, _ = hasher.Write(pubKey)
	_, _ = hasher.Write(msg)
	return hasher.Sum(nil)
}

func (s schnorrDigest) computeChallenge(r, pubKey, msg []byte) []byte {
	_, _ = s.hasher.Write(r)
	_, _ = s.hasher.Write(pubKey)
	_, _ = s.hasher.Write(msg)
	return s.hasher.Sum(nil)
}

type EcOperations struct{}

func (EcOperations) RequiredGas([]byte) uint64 {
	return 100
}

func (EcOperations) Run(input []byte) ([]byte, error) {
	if len(input) < 1 {
		return nil, fmt.Errorf("invalid length")
	}
	switch input[0] {
	case 0x10:
		return (&EcMultiply{}).Run(input[1:]) //	EcMul = 0x10
	case 0x11:
		return (&EcAdd{}).Run(input[1:]) //  EcAdd = 0x11
	case 0x12:
		return (&EcNeg{}).Run(input[1:]) //	EcNeg = 0x12
	case 0x13:
		return (&EcEqual{}).Run(input[1:]) //	EcEqual = 0x13
	case 0x14:
		return (&EcIsInfinity{}).Run(input[1:]) //	EcIsInfinity = 0x14
	case 0x15:
		return (&EcIsValid{}).Run(input[1:]) //	EcIsValid = 0x15
	case 0x16:
		return (&EcHash{}).Run(input[1:]) //	EcHash = 0x16
	case 0x17:
		return (&EcSumOfProducts{}).Run(input[1:]) //	EcSumOfProducts = 0x17
	case 0x18:
		return (&EcPairing{}).Run(input[1:]) //	EcPairing = 0x18
	case 0x30:
		return (&ScAdd{}).Run(input[1:]) //	ScAdd = 0x30
	case 0x31:
		return (&ScMul{}).Run(input[1:]) //	ScMul = 0x31
	case 0x32:
		return (&ScNeg{}).Run(input[1:]) //	ScNeg = 0x32
	case 0x33:
		return (&ScInv{}).Run(input[1:]) //	ScInvert = 0x33
	case 0x34:
		return (&ScSqrt{}).Run(input[1:]) //	ScSqrt = 0x34
	case 0x35:
		return (&ScEqual{}).Run(input[1:]) //	ScEqual = 0x35
	case 0x36:
		return (&ScIsZero{}).Run(input[1:]) //	ScIsZero = 0x36
	case 0x37:
		return (&ScIsValid{}).Run(input[1:]) //	ScIsValid = 0x37
	case 0x38:
		return (&ScFromWideBytes{}).Run(input[1:]) //	ScFromWideBytes = 0x38
	case 0x39:
		return (&ScHash{}).Run(input[1:]) //	ScHash = 0x39
	case 0x50:
		return (&EcdsaVerify{}).Run(input[1:]) //	EcdsaVerify = 0x50
	case 0x51:
		return (&SchnorrVerify1{}).Run(input[1:]) //	SchnorrVerify1 = 0x51
	case 0x52:
		return (&SchnorrVerify2{}).Run(input[1:]) //	SchnorrVerify2 = 0x52
	case 0x53:
		return (&BlsVerify{}).Run(input[1:]) //	BlsVerify = 0x53
	default:
		return nil, fmt.Errorf("invalid operation")
	}
}

type EcOps interface {
	Handle(processor curveHandler, input []byte) ([]byte, error)
	MinLength(processor curveHandler) int
}

type EcMultiply struct{}
type EcAdd struct{}
type EcNeg struct{}
type EcEqual struct{}
type EcIsInfinity struct{}
type EcIsValid struct{}
type EcHash struct{}
type EcSumOfProducts struct{}
type EcPairing struct{}
type ScAdd struct{}
type ScMul struct{}
type ScNeg struct{}
type ScInv struct{}
type ScSqrt struct{}
type ScEqual struct{}
type ScIsZero struct{}
type ScIsValid struct{}
type ScFromWideBytes struct{}
type ScHash struct{}
type EcdsaVerify struct{}
type SchnorrVerify1 struct{}
type SchnorrVerify2 struct{}
type BlsVerify struct{}

func (*EcMultiply) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcMultiply) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcMultiply) Handle(processor curveHandler, input []byte) (res []byte, err error) {
	var read int
	var points []curvey.Point
	var scalars []curvey.Scalar
	read, points, err = processor.InPoint(input, 1)

	if err != nil {
		return nil, err
	}
	if len(points) < 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got 0")
	}
	scalars, err = processor.InScalar(input[read:], 1)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 1 {
		return nil, fmt.Errorf("insufficient scalars, expected 1 but got 0")
	}
	pt := points[0].Mul(scalars[0])
	return processor.OutPoint(pt), nil
}

func (*EcMultiply) MinLength(processor curveHandler) int {
	return processor.PointSize() + scalarSize
}

func (*EcAdd) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcAdd) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcAdd) Handle(processor curveHandler, input []byte) ([]byte, error) {
	_, points, err := processor.InPoint(input, 2)
	if err != nil {
		return nil, err
	}
	if len(points) < 2 {
		return nil, fmt.Errorf("insufficient points, expected 2 but got %d", len(points))
	}
	pt := points[0].Add(points[1])
	return processor.OutPoint(pt), nil
}

func (*EcAdd) MinLength(processor curveHandler) int {
	return processor.PointSize() * 2
}

func (*EcNeg) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcNeg) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcNeg) Handle(processor curveHandler, input []byte) ([]byte, error) {
	_, points, err := processor.InPoint(input, 1)
	if err != nil {
		return nil, err
	}
	if len(points) < 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got 0")
	}
	return processor.OutPoint(points[0].Neg()), nil
}

func (*EcNeg) MinLength(processor curveHandler) int {
	return processor.PointSize()
}

func (*EcEqual) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcEqual) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcEqual) Handle(processor curveHandler, input []byte) ([]byte, error) {
	_, points, err := processor.InPoint(input, 2)
	if err != nil {
		return nil, err
	}
	if len(points) < 2 {
		return nil, fmt.Errorf("insufficient points, expected 2 but got %d", len(points))
	}
	if points[0].Equal(points[1]) {
		return []byte{1}, nil
	} else {
		return []byte{0}, nil
	}
}

func (*EcEqual) MinLength(processor curveHandler) int {
	return processor.PointSize() * 2
}

func (*EcIsInfinity) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcIsInfinity) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcIsInfinity) Handle(processor curveHandler, input []byte) ([]byte, error) {
	_, points, err := processor.InPoint(input, 1)
	if err != nil {
		return nil, err
	}
	if len(points) < 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got 0")
	}
	if points[0].IsIdentity() {
		return []byte{1}, nil
	} else {
		return []byte{0}, nil
	}
}

func (*EcIsInfinity) MinLength(processor curveHandler) int {
	return processor.PointSize()
}

func (*EcIsValid) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcIsValid) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcIsValid) Handle(processor curveHandler, input []byte) ([]byte, error) {
	_, points, err := processor.InPoint(input, 1)
	if err != nil {
		return nil, err
	}
	if len(points) < 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got 0")
	}
	if points[0].IsOnCurve() {
		return []byte{1}, nil
	} else {
		return []byte{0}, nil
	}
}

func (*EcIsValid) MinLength(processor curveHandler) int {
	return processor.PointSize()
}

func (*EcHash) RequiredGas([]byte) uint64 {
	return 60
}

func (ec *EcHash) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcHash) Handle(processor curveHandler, input []byte) ([]byte, error) {
	bi := new(big.Int).SetBytes(input[:32])
	ll := int(bi.Int64())
	if len(input[:32]) < ll {
		return nil, fmt.Errorf("invalid length")
	}
	pt := processor.Curve().NewIdentityPoint().Hash(input[32 : 32+ll])
	return processor.OutPoint(pt), nil
}

func (*EcHash) MinLength(curveHandler) int {
	return 33 // 32 bytes for the uint256 and at least 1 byte
}

func (*EcSumOfProducts) RequiredGas([]byte) uint64 {
	return 120
}

func (ec *EcSumOfProducts) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcSumOfProducts) Handle(processor curveHandler, input []byte) ([]byte, error) {
	bi := new(big.Int).SetBytes(input[:32])
	ll := int(bi.Int64())
	if len(input[32:]) < ll {
		return nil, fmt.Errorf("invalid length")
	}
	read, points, err := processor.InPoint(input[32:], ll)
	if err != nil {
		return nil, err
	}
	if len(points) < ll {
		return nil, fmt.Errorf("insufficient points, expected %d but got %d", ll, len(points))
	}
	scalars, err := processor.InScalar(input[read+32:], ll)
	if err != nil {
		return nil, err
	}
	if len(scalars) < ll {
		return nil, fmt.Errorf("insufficient scalars, expected %d but got %d", ll, len(scalars))
	}
	pt := processor.Curve().NewIdentityPoint().SumOfProducts(points, scalars)
	return processor.OutPoint(pt), nil
}

func (*EcSumOfProducts) MinLength(processor curveHandler) int {
	return processor.PointSize()*2 + scalarSize*2
}

func (*EcPairing) RequiredGas([]byte) uint64 {
	return 200
}

func (ec *EcPairing) Run(input []byte) ([]byte, error) {
	return executeCommand(ec, input)
}

func (*EcPairing) Handle(processor curveHandler, input []byte) ([]byte, error) {
	bi := new(big.Int).SetBytes(input[:32])
	cnt := int(bi.Int64())
	if len(input[:32]) < cnt {
		return nil, fmt.Errorf("invalid length")
	}
	buffer := input[32:]
	if cnt*96+cnt*192 > len(buffer) {
		return nil, fmt.Errorf("invalid length")
	}
	pairingPoints := make([]curvey.PairingPoint, cnt*2)
	for i := 0; i < cnt*2; i += 2 {
		pt, err := new(curvey.PointBls12381G1).FromAffineUncompressed(buffer[:96])
		if err != nil {
			return nil, err
		}
		pairingPoints[i] = pt.(*curvey.PointBls12381G1)
		buffer = buffer[96:]
	}
	for i := 1; i < cnt*2; i += 2 {
		pt, err := new(curvey.PointBls12381G2).FromAffineUncompressed(buffer[:192])
		if err != nil {
			return nil, err
		}
		pairingPoints[i] = pt.(*curvey.PointBls12381G2)
		buffer = buffer[192:]
	}
	return new(curvey.PointBls12381G1).MultiPairing(pairingPoints...).Bytes(), nil
}

func (*EcPairing) MinLength(curveHandler) int {
	return 48 + 96
}

func (*ScAdd) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScAdd) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScAdd) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 2)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 2 {
		return nil, fmt.Errorf("insufficient scalars, expected 2 but got %d", len(scalars))
	}
	s := scalars[0].Add(scalars[1])
	if s == nil {
		return []byte{}, fmt.Errorf("not supported")
	}
	return s.Bytes(), nil
}

func (*ScAdd) MinLength(curveHandler) int {
	return scalarSize * 2
}

func (*ScMul) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScMul) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScMul) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 2)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 2 {
		return nil, fmt.Errorf("insufficient scalars, expected 2 but got %d", len(scalars))
	}
	s := scalars[0].Mul(scalars[1])
	if s == nil {
		return []byte{}, fmt.Errorf("not supported")
	}
	return s.Bytes(), nil
}

func (*ScMul) MinLength(curveHandler) int {
	return scalarSize * 2
}

func (*ScNeg) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScNeg) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScNeg) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 1)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 1 {
		return nil, fmt.Errorf("insufficient scalars, expected 1 but got %d", len(scalars))
	}
	s := scalars[0].Neg()
	if s == nil {
		return []byte{}, fmt.Errorf("not supported")
	}
	return s.Bytes(), nil
}

func (*ScNeg) MinLength(curveHandler) int {
	return scalarSize
}

func (*ScInv) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScInv) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScInv) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 1)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 1 {
		return nil, fmt.Errorf("insufficient scalars, expected 1 but got %d", len(scalars))
	}
	s, err := scalars[0].Invert()
	if err != nil {
		return nil, err
	}
	if s == nil {
		return []byte{}, fmt.Errorf("not supported")
	}
	return s.Bytes(), nil
}

func (*ScInv) MinLength(curveHandler) int {
	return scalarSize
}

func (*ScSqrt) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScSqrt) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScSqrt) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 1)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 1 {
		return nil, fmt.Errorf("insufficient scalars, expected 1 but got %d", len(scalars))
	}
	s, err := scalars[0].Sqrt()
	if err != nil {
		return nil, err
	}
	if s == nil {
		return []byte{}, fmt.Errorf("not supported")
	}
	return s.Bytes(), nil
}

func (*ScSqrt) MinLength(curveHandler) int {
	return scalarSize
}

func (*ScEqual) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScEqual) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScEqual) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 2)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 2 {
		return nil, fmt.Errorf("insufficient scalars, expected 2 but got %d", len(scalars))
	}
	if scalars[0].Cmp(scalars[1]) == 0 {
		return []byte{1}, nil
	} else {
		return []byte{0}, nil
	}
}

func (*ScEqual) MinLength(curveHandler) int {
	return scalarSize * 2
}

func (*ScIsZero) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScIsZero) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScIsZero) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 1)
	if err != nil {
		return nil, err
	}
	if len(scalars) < 1 {
		return nil, fmt.Errorf("insufficient scalars, expected 1 but got %d", len(scalars))
	}
	if scalars[0].IsZero() {
		return []byte{1}, nil
	} else {
		return []byte{0}, nil
	}
}

func (*ScIsZero) MinLength(curveHandler) int {
	return scalarSize
}

func (*ScIsValid) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScIsValid) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScIsValid) Handle(processor curveHandler, input []byte) ([]byte, error) {
	scalars, err := processor.InScalar(input, 1)
	if err != nil {
		return []byte{0}, nil
	}
	if len(scalars) < 1 {
		return []byte{0}, nil
	}
	return []byte{1}, nil
}

func (*ScIsValid) MinLength(curveHandler) int {
	return scalarSize
}

func (*ScFromWideBytes) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScFromWideBytes) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScFromWideBytes) Handle(processor curveHandler, input []byte) ([]byte, error) {
	bi := new(big.Int).SetBytes(input[:32])
	ll := int(bi.Int64())
	if len(input[:32]) < ll {
		return nil, fmt.Errorf("invalid length")
	}
	s, err := processor.Curve().NewScalar().SetBytesWide(input[32 : 32+ll])
	if err != nil {
		return nil, err
	}
	if s == nil {
		return []byte{}, fmt.Errorf("not supported")
	}
	return s.Bytes(), nil
}

func (*ScFromWideBytes) MinLength(curveHandler) int {
	return 96
}

func (*ScHash) RequiredGas([]byte) uint64 {
	return 60
}

func (s *ScHash) Run(input []byte) ([]byte, error) {
	return executeCommand(s, input)
}

func (*ScHash) Handle(processor curveHandler, input []byte) ([]byte, error) {
	bi := new(big.Int).SetBytes(input[:32])
	ll := int(bi.Int64())
	if len(input[:32]) < ll {
		return nil, fmt.Errorf("invalid length")
	}
	s := processor.Curve().NewScalar().Hash(input[32 : 32+ll])
	return s.Bytes(), nil
}

func (*ScHash) MinLength(curveHandler) int {
	return 33 // 32 bytes for the uint256 and at least 1 byte
}

func (*EcdsaVerify) RequiredGas([]byte) uint64 {
	return 80
}

func (e *EcdsaVerify) Run(input []byte) ([]byte, error) {
	return executeCommand(e, input)
}

func (*EcdsaVerify) Handle(processor curveHandler, input []byte) ([]byte, error) {
	messageScalar, err := processor.InScalar(input, 1)
	if err != nil {
		return nil, err
	}
	if len(messageScalar) != 1 {
		return nil, fmt.Errorf("insufficient scalars, expected 1 but got %d", len(messageScalar))
	}
	read, points, err := processor.InPoint(input[32:], 1)
	if err != nil {
		return nil, err
	}
	if len(points) != 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got %d", len(points))
	}
	if points[0].IsIdentity() {
		return nil, fmt.Errorf("invalid public key")
	}
	if len(input[32+read:]) < 64 {
		return nil, fmt.Errorf("invalid length")
	}
	// r, s
	sigScalars, err := processor.InScalar(input[64+read:], 2)
	if err != nil {
		return nil, err
	}
	if sigScalars[0].IsZero() {
		return nil, fmt.Errorf("invalid signature")
	}

	sInv, err := sigScalars[1].Invert()
	if err != nil {
		// only returns an error if `s` is zero
		return nil, fmt.Errorf("invalid signature")
	}
	u1 := messageScalar[0].Mul(sInv)
	u2 := sigScalars[0].Mul(sInv)
	curve := processor.Curve()
	p := curve.ScalarBaseMult(u1).Add(points[0].Mul(u2))
	x := new(big.Int).SetBytes(p.ToAffineCompressed()[1:])
	// reduces bytes
	xSc, err := curve.NewScalar().SetBigInt(x)

	if xSc.Cmp(sigScalars[0]) == 0 {
		return []byte{1}, nil
	} else {
		return []byte{0}, nil
	}
}

func (*EcdsaVerify) MinLength(processor curveHandler) int {
	return scalarSize*3 + processor.PointSize()
}

func (*SchnorrVerify1) RequiredGas([]byte) uint64 {
	return 80
}

func (e *SchnorrVerify1) Run(input []byte) ([]byte, error) {
	return executeCommand(e, input)
}

func (*SchnorrVerify1) Handle(processor curveHandler, input []byte) ([]byte, error) {
	hasher, err := parseHash(input)
	if err != nil {
		return nil, err
	}
	if len(input[32:]) < 32 {
		return nil, fmt.Errorf("invalid length")
	}
	msg := input[32:64]

	read, points, err := processor.InPoint(input[64:], 1)
	if err != nil {
		return nil, err
	}
	if len(points) != 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got %d", len(points))
	}
	if points[0].IsIdentity() {
		return nil, fmt.Errorf("invalid public key")
	}
	offset := 64 + read
	r := input[offset : offset+processor.SchnorrPointSize()]
	if isAllZeros(r) {
		return nil, fmt.Errorf("invalid signature")
	}
	offset += processor.SchnorrPointSize()
	sigScalar, err := processor.InScalar(input[offset:], 1)
	if err != nil {
		return nil, err
	}
	if sigScalar[0].IsZero() {
		return nil, fmt.Errorf("invalid signature")
	}
	curve := processor.Curve()

	eInt := new(big.Int).SetBytes(hasher.computeChallenge(r, processor.SchnorrPoint(points[0]), msg))
	e, err := curve.NewScalar().SetBigInt(eInt)
	if err != nil {
		return nil, err
	}
	bigR := curve.ScalarBaseMult(sigScalar[0]).Sub(points[0].Mul(e))
	rBytes := processor.SchnorrPoint(bigR)
	if bigR.IsIdentity() || bytes.Compare(rBytes, r) != 0 {
		return []byte{0}, nil
	} else {
		return []byte{1}, nil
	}
}

func (*SchnorrVerify1) MinLength(processor curveHandler) int {
	return scalarSize*4 + processor.PointSize()
}

func (*SchnorrVerify2) RequiredGas([]byte) uint64 {
	return 80
}

func (e *SchnorrVerify2) Run(input []byte) ([]byte, error) {
	return executeCommand(e, input)
}

func (*SchnorrVerify2) Handle(processor curveHandler, input []byte) ([]byte, error) {
	hasher, err := parseHash(input)
	if err != nil {
		return nil, err
	}
	if len(input[32:]) < 32 {
		return nil, fmt.Errorf("invalid length")
	}
	msg := input[32:64]

	read, points, err := processor.InPoint(input[64:], 1)
	if err != nil {
		return nil, err
	}
	if len(points) != 1 {
		return nil, fmt.Errorf("insufficient points, expected 1 but got %d", len(points))
	}
	if points[0].IsIdentity() {
		return nil, fmt.Errorf("invalid public key")
	}
	offset := 64 + read
	r := input[offset : offset+processor.SchnorrPointSize()]
	if isAllZeros(r) {
		return nil, fmt.Errorf("invalid signature")
	}
	offset += processor.SchnorrPointSize()
	sigScalar, err := processor.InScalar(input[offset:], 1)
	if err != nil {
		return nil, err
	}
	if sigScalar[0].IsZero() {
		return nil, fmt.Errorf("invalid signature")
	}
	curve := processor.Curve()

	eInt := new(big.Int).SetBytes(hasher.computeChallenge(r, processor.SchnorrPoint(points[0]), msg))
	e, err := curve.NewScalar().SetBigInt(eInt)
	if err != nil {
		return nil, err
	}
	bigR := curve.ScalarBaseMult(sigScalar[0]).Add(points[0].Mul(e))
	rBytes := processor.SchnorrPoint(bigR)
	if bigR.IsIdentity() || bytes.Compare(rBytes, r) != 0 {
		return []byte{0}, nil
	} else {
		return []byte{1}, nil
	}
}

func (*SchnorrVerify2) MinLength(processor curveHandler) int {
	return scalarSize*4 + processor.PointSize()
}

func (*BlsVerify) RequiredGas([]byte) uint64 {
	return 80
}

func (e *BlsVerify) Run(input []byte) ([]byte, error) {
	return executeCommand(e, input)
}

func (*BlsVerify) Handle(processor curveHandler, input []byte) ([]byte, error) {
	bi := new(big.Int).SetBytes(input[:32])
	ll := int(bi.Int64())
	if len(input[:32]) < ll {
		return nil, fmt.Errorf("invalid length")
	}
	msg := input[32 : 32+ll]
	if err := processor.BlsVerify(msg, input[32+ll:]); err != nil {
		return []byte{0}, nil
	} else {
		return []byte{1}, nil
	}
}

func (*BlsVerify) MinLength(processor curveHandler) int {
	return 32 + processor.PointSize()*3 // size of message and two points but one point is 2X the other
}

func isAllZeros(buf []byte) bool {
	res := true
	for _, b := range buf {
		res = res && (b == 0)
	}
	return res
}
