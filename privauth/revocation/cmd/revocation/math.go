// math provides cryptographic utilities: elliptic curve ops and hashing
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func RandScalar() *big.Int {
	res, _ := rand.Int(rand.Reader, fr.Modulus())
	return res
}
func RandPoint() bn254.PointAffine {
	params, _ := twistededwards.GetCurveParams(tedwards.BN254)
	var G bn254.PointAffine
	G.X.SetBigInt(params.Base[0])
	G.Y.SetBigInt(params.Base[1])
	rs := RandScalar()
	res := *new(bn254.PointAffine).ScalarMultiplication(&G, rs)
	return res
}

func ScalarAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b)
}

func ScalarMul(a, b *big.Int) *big.Int {
	params, _ := twistededwards.GetCurveParams(tedwards.BN254)
	return new(big.Int).Mod(new(big.Int).Mul(a, b), params.Order)
}

func PointAdd(a, b bn254.PointAffine) bn254.PointAffine {
	return *new(bn254.PointAffine).Add(&a, &b)
}

func PointExp(p bn254.PointAffine, s *big.Int) bn254.PointAffine {
	return *new(bn254.PointAffine).ScalarMultiplication(&p, s)
}

func PointAssign(p bn254.PointAffine) twistededwards.Point {
	return twistededwards.Point{X: p.X, Y: p.Y}
}

func sortScalars(arr []*big.Int) {
	for i := 0; i < len(arr)-1; i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[i].Cmp(arr[j]) > 0 {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
}

func concatBigInts(a, b, c *big.Int) []byte {
	aBytes := a.Bytes()
	bBytes := b.Bytes()
	cBytes := c.Bytes()
	totalLen := len(aBytes) + len(bBytes) + len(cBytes)
	result := make([]byte, 0, totalLen)
	result = append(result, aBytes...)
	result = append(result, bBytes...)
	result = append(result, cBytes...)
	return result
}

// printMemUsage prints memory usage
func printMemUsage(phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("%s - memory: Alloc = %v MiB, TotalAlloc = %v MiB, Sys = %v MiB\n",
		phase,
		m.Alloc/1024/1024,
		m.TotalAlloc/1024/1024,
		m.Sys/1024/1024)
}
func calculateBitSize(v interface{}) int {
	switch val := v.(type) {
	case twistededwards.Point:
		xBits := bitSizeOfVariable(val.X)
		yBits := bitSizeOfVariable(val.Y)
		return xBits + yBits
	case *big.Int:
		return val.BitLen()
	case frontend.Variable:
		return bitSizeOfVariable(val)
	default:
		return 0
	}
}
func bitSizeOfVariable(v frontend.Variable) int {

	if i, ok := v.(*big.Int); ok {
		return i.BitLen()
	}
	return 254
}

// ComputeMiddHash computes SHA256(Rand || ID[20] || Ts[15] || Te[15] || Attrs)
func ComputeMiddHash(Rand *big.Int, ID [20]*big.Int, Ts, Te [15]*big.Int, Attrs []*big.Int) ([]byte, error) {
	var buf bytes.Buffer

	randBytes := Rand.Bytes()
	if _, err := buf.Write(randBytes); err != nil {
		return nil, fmt.Errorf("failed to write Rand: %v", err)
	}

	for i := 0; i < 20; i++ {
		idBytes := ID[i].Bytes()
		if _, err := buf.Write(idBytes); err != nil {
			return nil, fmt.Errorf("failed to write ID[%d]: %v", i, err)
		}
	}

	for i := 0; i < 15; i++ {
		tsBytes := Ts[i].Bytes()
		if _, err := buf.Write(tsBytes); err != nil {
			return nil, fmt.Errorf("failed to write Ts[%d]: %v", i, err)
		}
	}

	for i := 0; i < 15; i++ {
		teBytes := Te[i].Bytes()
		if _, err := buf.Write(teBytes); err != nil {
			return nil, fmt.Errorf("failed to write Te[%d]: %v", i, err)
		}
	}

	for i := 0; i < len(Attrs); i++ {
		attrBytes := Attrs[i].Bytes()
		if _, err := buf.Write(attrBytes); err != nil {
			return nil, fmt.Errorf("failed to write Attrs[%d]: %v", i, err)
		}
	}

	hash := sha256.Sum256(buf.Bytes())
	return hash[:], nil
}
