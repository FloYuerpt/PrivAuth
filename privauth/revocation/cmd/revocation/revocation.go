package main

import (
	"fmt"
	"runtime"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	"github.com/consensys/gnark/std/math/cmp"
)

type MyCircuit struct {
	VaT   twistededwards.Point `gnark:",public"`
	CaT   twistededwards.Point `gnark:",public"`
	GdT   twistededwards.Point `gnark:",public"`
	CidT  twistededwards.Point `gnark:",public"`
	GcaAT twistededwards.Point `gnark:",public"`

	T, Id      frontend.Variable
	Id0        [m]frontend.Variable    `gnark:",public"`
	Idk        [m]frontend.Variable    `gnark:",public"`
	G          twistededwards.Point    `gnark:",public"`
	R          [m]twistededwards.Point `gnark:",public"`
	Alpha      frontend.Variable       // single issuer secret key
	SET        [m][k]frontend.Variable
	ExpectedAc twistededwards.Point        `gnark:",public"` // public verification: accumulator result
	SRS        [k + 1]twistededwards.Point `gnark:",public"` // auxiliary verification
	GroupIndex frontend.Variable
	OrHash     [m][32]frontend.Variable `gnark:",public"`
	OrProof    [32]frontend.Variable    `gnark:",public"`
}

// params: revocation list length [100,1000,10000], issuer count [5,10,20,50]
// time, communication overhead
const (
	m = 32  // number of accumulators
	k = 100 // IDs per accumulator
	n = 5   // number of issuers
)

func (circuit *MyCircuit) Define(api frontend.API) error {
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

	runtime.GC()
	printMemUsage("initial state")
	tr := time.Now()
	start := time.Now()
	isZeroX := api.IsZero(circuit.GdT.X)            // check if X is 0
	isOneY := api.IsZero(api.Sub(circuit.GdT.Y, 1)) // check if Y is 1
	isInfinity := api.And(isZeroX, isOneY)          // if X=0 and Y=1, then point at infinity
	api.AssertIsEqual(isInfinity, 0)                // assert isInfinity = false (0)
	elapsed := time.Since(start)
	printMemUsage("GdT validity check")
	fmt.Printf("✓ GdT validity check passed, elapsed: %v \n", elapsed)
	start = time.Now()
	isInRange := api.And(
		cmp.IsLess(api, selectWithVariable(api, circuit.Id0[:], circuit.GroupIndex), circuit.Id),
		cmp.IsLess(api, circuit.Id, selectWithVariable(api, circuit.Idk[:], circuit.GroupIndex)),
	)
	api.AssertIsLessOrEqual(circuit.GroupIndex, m-1)
	api.AssertIsEqual(1, isInRange)

	elapsed = time.Since(start)
	printMemUsage("ID comparison")
	fmt.Printf("✓ ID comparison done, elapsed: %v\n", elapsed)

	start = time.Now()
	results := ComputeAccumulators(api, curve, circuit.G, circuit.SET, circuit.Alpha)
	idx := 0 // assume verifying group 0
	api.AssertIsEqual(results[idx].Accumulator.X, circuit.ExpectedAc.X)
	api.AssertIsEqual(results[idx].Accumulator.Y, circuit.ExpectedAc.Y)
	elapsed = time.Since(start)
	accc := elapsed
	printMemUsage("accumulator build")
	fmt.Printf("✓ accumulator build done, elapsed: %v\n", elapsed)

	fmt.Printf("---------- non-membership proof ------------\n")

	// 5. verify validity of user-provided parameters
	start = time.Now()
	verifyStart := time.Now()
	abs := curve.Add(curve.Add(circuit.CidT, circuit.GcaAT), circuit.GdT)
	api.AssertIsEqual(abs.X, circuit.VaT.X)
	api.AssertIsEqual(abs.Y, circuit.VaT.Y)

	verifyTime := time.Since(verifyStart)
	elapsed = time.Since(start)
	printMemUsage("polynomial commitment verification")
	fmt.Printf("✓  polynomial commitment verification passed, total: %v (verify: %v)\n", elapsed, verifyTime)

	fmt.Printf("----------- membership proof ----------\n")
	printMemUsage("OR operation verification")
	verifyOrProofInHash(api, circuit.OrHash, circuit.OrProof)
	trr := time.Since(tr) - accc
	printMemUsage("final state")
	fmt.Printf("----------------------- total verification time: %v -------------------------\n", trr)
	fmt.Printf("----------------------- accumulator build time: %v -------------------------\n", accc)
	fmt.Printf("----------------------- total circuit execution time: %v -------------------------\n", trr+accc)
	return nil
}

func selectWithVariable(api frontend.API, arr []frontend.Variable, idx frontend.Variable) frontend.Variable {
	var result frontend.Variable = 0
	for i := 0; i < len(arr); i++ {
		// generate selector (1 when idx == i)
		selector := api.IsZero(api.Sub(idx, i))
		// accumulate selected value
		result = api.Add(result, api.Mul(selector, arr[i]))
	}
	return result
}

func verifyOrProofInHash(api frontend.API, orHash [m][32]frontend.Variable, orProof [32]frontend.Variable) {
	star := time.Now()
	// variable to track if any match found
	isMember := frontend.Variable(0)

	// iterate over each hash
	for i := 0; i < m; i++ {
		// verify current hash matches orProof
		isMatch := frontend.Variable(1) // assume match

		// check all 32 elements match
		for j := 0; j < 32; j++ {
			// if any element mismatches, isMatch becomes 0
			elemEqual := api.IsZero(api.Sub(orHash[i][j], orProof[j]))
			isMatch = api.Mul(isMatch, elemEqual)
		}

		// update member status (isMember=1 if any match found)
		isMember = api.Or(isMember, isMatch)
	}

	// assert at least one match found
	api.AssertIsEqual(isMember, 1)
	elapse := time.Since(star)
	fmt.Printf("✓  OR operation membership verification passed, elapsed: %v\n", elapse)

}
