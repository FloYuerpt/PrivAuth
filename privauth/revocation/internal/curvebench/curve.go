// curve provides benchmark for emulated elliptic curve constraint count
package curvebench

import (
	"fmt"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type ScalarMulTest[T, R emulated.FieldParams] struct {
	P, Q sw_emulated.AffinePoint[T]
	S    emulated.Element[R]
}

func (c *ScalarMulTest[T, R]) Define(api frontend.API) error {
	cr, err := sw_emulated.New[T, R](api, sw_emulated.GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestScalarMul[T, R emulated.FieldParams]() int {
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ScalarMulTest[T, R]{})
	return ccs.GetNbConstraints()
}

// TestAllEmulatedCurve runs scalar multiplication constraint count benchmark for all emulated curves
func TestAllEmulatedCurve() {
	typeAndResults := map[string]int{
		"emparams.Secp256k1Fp": TestScalarMul[emparams.Secp256k1Fp, emparams.Secp256k1Fr](),
		"emparams.BN254Fp":     TestScalarMul[emparams.BN254Fp, emparams.BN254Fr](),
		"emparams.BLS12381Fp":  TestScalarMul[emparams.BLS12381Fp, emparams.BLS12381Fr](),
		"emparams.P256Fp":      TestScalarMul[emparams.P256Fp, emparams.P256Fr](),
		"emparams.P384Fp":   TestScalarMul[emparams.P384Fp, emparams.P384Fr](),
		"emparams.BW6761Fp": TestScalarMul[emparams.BW6761Fp, emparams.BW6761Fr](),
	}

	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range typeAndResults {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value < ss[j].Value
	})
	for _, pair := range ss {
		fmt.Printf("%s: %d\n", pair.Key, pair.Value)
	}
}
