package deriver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/mikelodder7/curvey"
	"github.com/mikelodder7/curvey/native"
)

type CurveType int

const (
	P256 CurveType = iota
	K256
)

type Deriver struct {
	value curvey.Scalar
}

type DerivePublicKey struct{}

func (d *DerivePublicKey) RequiredGas([]byte) uint64 {
	return 1000
}

func (d *DerivePublicKey) Run(input []byte) ([]byte, error) {
	// 1st arg is a byte for the curve type, 0 is Nist Prime256, 1 is secp256k1
	// 2nd arg is a 4 byte big-endian integer for the number of bytes in id
	// 3rd arg is the byte sequence for id
	// 4th arg is a 4 byte big-endian integer for the number of bytes in cxt
	// 5th arg is the byte sequence for cxt
	// 6th arg is a 4 byte big-endian integer for the number of root keys
	// 7th arg is a variable number of root keys each 33 bytes in length
	var defaultRes []byte
	var err error

	params := new(deriveParams)

	// TODO: DEBUGGING code for now, remove for production
	i := 0
	for l := len(input); i < l; i++ {
		if err = params.UnmarshalBinary(input[i:]); err == nil {
			break
		}
	}

	if err != nil {
		err = params.UnmarshalBinary(input)
		return defaultRes, err
	}
	deriver, err := NewDeriver(params.curveType, params.id, params.cxt)
	if err != nil {
		return defaultRes, err
	}

	derivedKey := deriver.ComputePublicKey(params.rootKeys)
	output := derivedKey.ToAffineCompressed()
	output = append([]byte{byte(len(output))}, output...)
	return output, nil
}

type deriveParams struct {
	curveType CurveType
	id, cxt   []byte
	rootKeys  []curvey.Point
}

func (d *deriveParams) MarshalBinary() ([]byte, error) {
	var n int
	var err error
	length := len(d.id) + len(d.cxt) + 13 + len(d.rootKeys)*33
	buffer := new(bytes.Buffer)
	buffer.Grow(length)
	// WriteByte always returns nil
	_ = buffer.WriteByte(byte(d.curveType))

	if err = binary.Write(buffer, binary.BigEndian, uint32(len(d.id))); err != nil {
		return nil, err
	}
	if n, _ = buffer.Write(d.id); n != len(d.id) {
		return nil, errors.New("unable to write 'id'")
	}
	if err = binary.Write(buffer, binary.BigEndian, uint32(len(d.cxt))); err != nil {
		return nil, err
	}
	if n, _ = buffer.Write(d.cxt); n != len(d.cxt) {
		return nil, err
	}
	if err = binary.Write(buffer, binary.BigEndian, uint32(len(d.rootKeys))); err != nil {
		return nil, err
	}
	for _, pt := range d.rootKeys {
		bb := pt.ToAffineCompressed()
		if n, _ = buffer.Write(bb); n != len(bb) {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func (d *deriveParams) UnmarshalBinary(input []byte) error {
	var curveType CurveType
	inputLen := len(input)
	var curve *curvey.Curve
	switch input[0] {
	case 0:
		curveType = P256
		curve = curvey.P256()
	case 1:
		curveType = K256
		curve = curvey.K256()
	default:
		return fmt.Errorf("invalid curve type: %v", input)
	}

	offset := 1
	if offset+4 > inputLen {
		return fmt.Errorf("invalid length: %v", input)
	}
	idLen := int(binary.BigEndian.Uint32(input[offset : offset+4]))
	offset += 4
	if offset+idLen > inputLen || idLen == 0 {
		return fmt.Errorf("invalid length: %v", input)
	}
	id := input[offset : offset+idLen]
	offset += idLen
	if offset+4 > inputLen {
		return fmt.Errorf("invalid length: %v", input)
	}
	cxtLen := int(binary.BigEndian.Uint32(input[offset : offset+4]))
	offset += 4
	if offset+cxtLen > inputLen || cxtLen == 0 {
		return fmt.Errorf("invalid length: %v", input)
	}
	cxt := input[offset : offset+cxtLen]
	offset += cxtLen
	if offset+4 > inputLen {
		return fmt.Errorf("invalid length: %v", input)
	}
	pksCnt := int(binary.BigEndian.Uint32(input[offset : offset+4]))
	offset += 4

	if pksCnt == 0 || (offset+pksCnt*33) > inputLen {
		return fmt.Errorf("invalid length %v", input)
	}

	pks := make([]curvey.Point, pksCnt)
	for i := 0; offset < inputLen && i < pksCnt; offset += 33 {
		if offset+33 > inputLen {
			return fmt.Errorf("invalid length: %v", input)
		}
		pk, err := curve.Point.FromAffineCompressed(input[offset : offset+33])
		if err != nil {
			return err
		}
		pks[i] = pk
		i++
	}

	d.id = id
	d.cxt = cxt
	d.curveType = curveType
	d.rootKeys = pks
	return nil
}

func NewDeriver(curveType CurveType, id, cxt []byte) (*Deriver, error) {
	xmd := native.ExpandMsgXmd(native.EllipticPointHasherSha256(), id, cxt, 48)
	var tmp [64]byte
	copy(tmp[:48], reverseScalarBytes(xmd))

	var value curvey.Scalar
	var err error
	switch curveType {
	case K256:
		value, err = curvey.K256().NewScalar().SetBytesWide(tmp[:])
	case P256:
		value, err = curvey.P256().NewScalar().SetBytesWide(tmp[:])
	default:
		return nil, fmt.Errorf("invalid curve type")
	}
	if err != nil {
		return nil, err
	}

	return &Deriver{
		value,
	}, nil
}

func (d *Deriver) ComputeSecretKey(rootKeys []curvey.Scalar) curvey.Scalar {
	res := d.value.Zero()

	// Compute the polynomial value using Horner's Method
	for i := len(rootKeys) - 1; i >= 0; i-- {
		res = res.Mul(d.value)
		res = res.Add(rootKeys[i])
	}

	return res
}

func (d *Deriver) ComputePublicKey(rootKeys []curvey.Point) curvey.Point {
	powers := make([]curvey.Scalar, len(rootKeys))
	powers[0] = d.value.One()
	powers[1] = d.value.Clone()
	for i := 2; i < len(rootKeys); i++ {
		powers[i] = powers[i-1].Mul(d.value)
	}
	return d.value.Point().SumOfProducts(rootKeys, powers)
}

func reverseScalarBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}
