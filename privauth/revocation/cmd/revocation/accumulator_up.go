package main

import (
	"fmt"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type upCircuit struct {
	VaTG  twistededwards.Point `gnark:",public"`
	CaTG  twistededwards.Point `gnark:",public"`
	GdTG  twistededwards.Point `gnark:",public"`
	CidTG twistededwards.Point `gnark:",public"`
	CaATG twistededwards.Point `gnark:",public"`
}

func (circuit *upCircuit) Define(api frontend.API) error {
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

	start := time.Now()
	abs := curve.Add(curve.Add(circuit.CidTG, circuit.CaATG), circuit.GdTG)
	api.AssertIsEqual(abs.X, circuit.VaTG.X)
	api.AssertIsEqual(abs.Y, circuit.VaTG.Y)

	elapsed := time.Since(start)
	printMemUsage("polynomial commitment verification")
	fmt.Printf("✓  polynomial commitment verification passed, total: %v \n", elapsed)
	return nil
}
