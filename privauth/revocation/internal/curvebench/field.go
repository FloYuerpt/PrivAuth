// field provides benchmark for emulated field operation constraint count
package curvebench

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type FieldCircuit[T emulated.FieldParams] struct {
	X, Y, Res emulated.Element[T]
}

func (circuit *FieldCircuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	tmp := field.Mul(&circuit.X, &circuit.Y)
	field.AssertIsEqual(tmp, &circuit.Res)
	return nil
}

func TestEmulatedField[T emulated.FieldParams]() int {
	var circuit, assignment FieldCircuit[T]
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)

	assignment.X = emulated.ValueOf[T]("26959946673427741531515197488526605382048662297355296634326893985793")
	assignment.Y = emulated.ValueOf[T]("53919893346855483063030394977053210764097324594710593268653787971586")
	var a, b, c big.Int
	a.SetString("26959946673427741531515197488526605382048662297355296634326893985793", 10)
	b.SetString("53919893346855483063030394977053210764097324594710593268653787971586", 10)
	var temp T
	c.Mod(new(big.Int).Mul(&a, &b), temp.Modulus())
	assignment.Res = emulated.ValueOf[T](c)

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		fmt.Println("invalid proof")
	}
	return ccs.GetNbConstraints()
}

// TestAllEmulatedField runs multiplication constraint count benchmark for all emulated fields
func TestAllEmulatedField() {
	typeAndResults := map[string]int{
		"emparams.Goldilocks":   TestEmulatedField[emparams.Goldilocks](),
		"emparams.Secp256k1Fp":  TestEmulatedField[emparams.Secp256k1Fp](),
		"emparams.Secp256k1Fr":  TestEmulatedField[emparams.Secp256k1Fr](),
		"emparams.BN254Fp":      TestEmulatedField[emparams.BN254Fp](),
		"emparams.BN254Fr":      TestEmulatedField[emparams.BN254Fr](),
		"emparams.BLS12377Fp":   TestEmulatedField[emparams.BLS12377Fp](),
		"emparams.BLS12381Fp":   TestEmulatedField[emparams.BLS12381Fp](),
		"emparams.BLS12381Fr":   TestEmulatedField[emparams.BLS12381Fr](),
		"emparams.P256Fp":       TestEmulatedField[emparams.P256Fp](),
		"emparams.P256Fr":      TestEmulatedField[emparams.P256Fr](),
		"emparams.P384Fp":    TestEmulatedField[emparams.P384Fp](),
		"emparams.P384Fr":    TestEmulatedField[emparams.P384Fr](),
		"emparams.BW6761Fp":  TestEmulatedField[emparams.BW6761Fp](),
		"emparams.BW6761Fr":  TestEmulatedField[emparams.BW6761Fr](),
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
