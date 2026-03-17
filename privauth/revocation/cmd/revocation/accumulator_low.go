package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type AccumulatorWithV struct {
	Accumulator twistededwards.Point // accumulator curve point G^v(a)
	V           frontend.Variable    // scalar v(a) = ∏(a + id_j)
}

// ComputeAccumulators computes accumulator ac = G^v(a) per group, where v(a) = ∏(a + id_j) (j ∈ [0, k-1])
func ComputeAccumulators(
	api frontend.API,
	curve twistededwards.Curve,
	G twistededwards.Point, // curve generator
	SET [m][k]frontend.Variable, // SET: m groups, k ids per group
	a frontend.Variable, // random scalar a
) []AccumulatorWithV {
	mm := len(SET)
	kk := len(SET[0])
	results := make([]AccumulatorWithV, mm)

	for i := 0; i < mm; i++ {
		// compute v(a) = ∏(a + id_j)
		v := frontend.Variable(1)
		for j := 0; j < kk; j++ {
			v = api.Mul(v, api.Add(a, SET[i][j])) // v *= (a + id_j)
		}

		// compute ac = G^v(a)
		accumulator := curve.ScalarMul(G, v)
		results[i] = AccumulatorWithV{
			Accumulator: accumulator,
			V:           v,
		}
	}
	return results
}

// computePlainAccumulator computes accumulator in plaintext
func computePlainAccumulator(
	ids []*big.Int, // list of id (length k)
	a *big.Int, // random scalar a
	G bn254.PointAffine, // elliptic curve base point
) (bn254.PointAffine, big.Int) {
	v := big.NewInt(1)
	mod := fr.Modulus()

	for _, id := range ids {
		sum := new(big.Int).Add(a, id)
		v.Mul(v, sum)
		v.Mod(v, mod)
	}
	ac := new(bn254.PointAffine).ScalarMultiplication(&G, v)
	return *ac, *v
}
