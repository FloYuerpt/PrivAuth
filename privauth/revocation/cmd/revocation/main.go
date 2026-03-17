package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type BitSizeStats struct {
	CaT   int
	GdT   int
	VaT   int
	GcaAT int
	CidT  int
	Id    int
	Total int
}

var (
	globalVaT   bn254.PointAffine // accumulate all PointExp(Idc, t)
	globalCaT   bn254.PointAffine // accumulate all PointExp(gCa, t)
	globalGdT   bn254.PointAffine // accumulate all PointExp(gD, t)
	globalCidT  bn254.PointAffine // accumulate all PointExp(gCaId, t)
	globalGcaAT bn254.PointAffine // accumulate all PointExp(gCaA, t)
)

func init() {
	// initialize global variables to point at infinity
	globalVaT.X.SetZero()
	globalVaT.Y.SetOne() // point at infinity in affine coords is (0,1)
	globalCaT = globalVaT
	globalGdT = globalVaT
	globalCidT = globalVaT
	globalGcaAT = globalVaT
}
func main() {
	t := RandScalar()  // random mask
	id := RandScalar() // user ID
	a := RandScalar()  // issuer secret key
	var upc upCircuit

	for numCA := 0; numCA < n; numCA++ {
		fmt.Printf("------------------------------------------- group %d verification started -------------------------------------------\n", numCA+1)
		var assignment MyCircuit
		params, _ := twistededwards.GetCurveParams(tedwards.BN254)
		var G bn254.PointAffine
		G.X.SetBigInt(params.Base[0])
		G.Y.SetBigInt(params.Base[1])
		//----------------- SHA256 data concatenation -----------------
		Rand := big.NewInt(123456789)
		ID := [20]*big.Int{}
		for i := 0; i < 20; i++ {
			ID[i] = RandScalar()
		}
		Ts := [15]*big.Int{}
		Te := [15]*big.Int{}
		for i := 0; i < 15; i++ {
			Ts[i] = big.NewInt(int64(100 + i))
			Te[i] = big.NewInt(int64(200 + i))
		}
		Attrs := make([]*big.Int, 10)
		for i := 0; i < 10; i++ {
			Attrs[i] = big.NewInt(int64(300 + i))
		}
		hash, er3 := ComputeMiddHash(Rand, ID, Ts, Te, Attrs)
		if er3 != nil {
			panic(er3)
		}
		fmt.Printf("SHA-256 hash result: %x\n", hash)
		//----------------- SET generation -----------------
		SET := make([][]*big.Int, m)
		CRL := make([]*big.Int, m*k)
		for i := 0; i < m*k; i++ {
			CRL[i] = RandScalar()
		}
		sortScalars(CRL)
		idx := -1
		for i := 0; i < m; i++ {
			SET[i] = CRL[i*k : (i+1)*k]
			if idx == -1 && SET[i][0].Cmp(id) <= 0 && id.Cmp(SET[i][k-1]) <= 0 {
				idx = i
			}
		}
		if idx == -1 {
			panic("id not in any range")
		}

		if len(SET) == 0 || len(SET[0]) == 0 {
			panic("SET not properly initialized")
		}
		for i := 0; i < m; i++ {
			if len(SET[i]) == 0 {
				panic(fmt.Sprintf("SET[%d] is empty", i))
			}
		}
		fmt.Printf("✓  ID dataset generated, total IDs: %d, accumulators: %d, IDs per accumulator: %d \n", m*k, m, k)
		// min/max per group
		id0 := make([]*big.Int, m)
		idk := make([]*big.Int, m)

		for i := 0; i < m; i++ {
			id0[i] = SET[i][0]
			idk[i] = SET[i][k-1]
		}

		r := make([]bn254.PointAffine, m)
		for i := 0; i < m; i++ {
			r[i] = RandPoint()
		}
		expectedAc, _ := computePlainAccumulator(SET[0], a, G)
		// ID index
		groupIndex := frontend.Variable(0)
		var Index int // default group index
		for i := 0; i < m; i++ {
			if id.Cmp(id0[i]) >= 0 && id.Cmp(idk[i]) <= 0 {
				groupIndex = i
				Index = i
				break
			}
		}
		fmt.Printf("User ID %d belongs to group %d \n", id, groupIndex)
		Idc, _ := computePlainAccumulator(SET[Index][:], a, G)
		//----------------- member set generation -----------------
		var varAll [m]big.Int
		mod := ecc.BN254.ScalarField()
		modNbBytes := len(mod.Bytes())
		merkleStart := time.Now()
		for i := 0; i < m; i++ { // compute V(a) for each accumulator
			_, varAll[i] = computePlainAccumulator(SET[i][:], a, G)
		}
		var b []byte
		for j := uint64(0); j < m; j++ {
			b = concatBigInts(&varAll[j], id0[j], idk[j]) // concat varall||id0||idk
			b = b[:modNbBytes-1]
			hashBytes := sha256.Sum256(b)
			for k := 0; k < 32; k++ {
				assignment.OrHash[j][k] = frontend.Variable(hashBytes[k])
			}
			if j == uint64(Index) {
				hash := sha256.Sum256(b)
				for k := 0; k < 32; k++ {
					assignment.OrProof[k] = frontend.Variable(hash[k])
				}
				fmt.Printf("SHA256 embedded")
			}
		}
		merkleDuration := time.Since(merkleStart)
		fmt.Printf("SHA256 generation time: %v\n", merkleDuration)

		//----------------- auxiliary data generation -----------------
		r[idx] = PointExp(Idc, t)
		srs := make([]bn254.PointAffine, k+1)
		currentPower := new(big.Int).Set(a)
		for i := 0; i <= k; i++ {
			srs[i] = PointExp(G, currentPower)           // G^(a^{i+1})
			currentPower.Mul(currentPower, a)            // a^{i+1} -> a^{i+2}
			currentPower.Mod(currentPower, fr.Modulus()) // mod
		}
		//---------------- non-membership proof -----------------
		polyCommitStart := time.Now()
		// polynomial assignment
		polyCoeffs := make([]*big.Int, k)
		for j := 0; j < k; j++ {
			polyCoeffs[j] = new(big.Int).SetInt64(0) // Initialize with default value (0)
		}
		for i := 0; i < m; i++ {
			if Index == i {
				for j := 0; j < k; j++ {
					polyCoeffs[j] = SET[i][j]
				}
				break
			}
		}
		// non-membership proof
		var gCa bn254.PointAffine
		gCa.ScalarMultiplication(&srs[0], polyCoeffs[0]) // G^(a * c_0)
		for j := 1; j < k; j++ {
			var term bn254.PointAffine
			term.ScalarMultiplication(&srs[j], polyCoeffs[j]) // G^[{a^{j+1}} * c_j]
			gCa.Add(&gCa, &term)
		}
		// compute G^[c(a)a]
		var gCaA bn254.PointAffine
		gCaA.ScalarMultiplication(&srs[1], polyCoeffs[0]) // G^{a^2} * c_0
		for j := 1; j < k; j++ {
			var term bn254.PointAffine
			term.ScalarMultiplication(&srs[j+1], polyCoeffs[j]) // G^{a^{j+2}} * c_j
			gCaA.Add(&gCaA, &term)
		}
		// compute G^{c(a)*id}
		var gCaId bn254.PointAffine
		gCaId.ScalarMultiplication(&gCa, id)
		// compute G^{c(a)(id + a)}
		var gCaIdPlusA bn254.PointAffine
		gCaIdPlusA.Add(&gCaId, &gCaA)
		//------------- solve d -------------
		// compute inverse of G^{c(a)(id + a)}
		var gCaIdPlusAInv bn254.PointAffine
		gCaIdPlusAInv.Neg(&gCaIdPlusA)
		var gD bn254.PointAffine
		gD.Add(&Idc, &gCaIdPlusAInv)
		polyCommitDuration := time.Since(polyCommitStart)
		fmt.Printf("Polynomial commitment proof generation time: %v\n", polyCommitDuration)

		//assignment
		assignment.CaT = PointAssign(PointExp(gCa, t)) // G^(c(a)*t)
		assignment.GdT = PointAssign(PointExp(gD, t))  // G^(d*t)
		assignment.G = PointAssign(G)
		assignment.VaT = PointAssign(PointExp(Idc, t)) //G^(v(a)*t)
		assignment.Id = id
		assignment.ExpectedAc = PointAssign(expectedAc)
		assignment.Alpha = a
		assignment.CidT = PointAssign(PointExp(gCaId, t))
		assignment.GroupIndex = groupIndex
		assignment.GcaAT = PointAssign(PointExp(gCaA, t))
		for i := 0; i < m; i++ {
			for j := 0; j < k; j++ {
				assignment.SET[i][j] = SET[i][j] // direct assignment
			}
		}
		for i := 0; i < m; i++ {
			assignment.Id0[i] = id0[i]
			assignment.Idk[i] = idk[i]
			assignment.R[i] = PointAssign(r[i])
		}
		assignment.T = t
		for i := 0; i <= k; i++ {
			assignment.SRS[i] = PointAssign(srs[i])
		}
		//
		var circuit MyCircuit
		ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		pk, vk, _ := groth16.Setup(ccs)

		witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		publicWitness, _ := witness.Public()
		proof, _ := groth16.Prove(ccs, pk, witness)
		err := groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			fmt.Println("invalid proof")
		}
		gvt := PointExp(Idc, t)
		globalVaT.Add(&globalVaT, &gvt)
		upc.VaTG = PointAssign(globalVaT)

		gct := PointExp(gCa, t)
		globalCaT.Add(&globalCaT, &gct)
		upc.CaTG = PointAssign(globalCaT)

		gdt := PointExp(gD, t)
		globalGdT.Add(&globalGdT, &gdt)
		upc.GdTG = PointAssign(globalGdT)

		gcidt := PointExp(gCaId, t)
		globalCidT.Add(&globalCidT, &gcidt)
		upc.CidTG = PointAssign(globalCidT)

		gcaAt := PointExp(gCaA, t)
		globalGcaAT.Add(&globalGcaAT, &gcaAt)
		upc.CaATG = PointAssign(globalGcaAT)
		fmt.Printf("------------------------------------------- group %d verification succeeded ------------------------------------------------\n", numCA+1)

		currentStats := BitSizeStats{
			CaT:   calculateBitSize(assignment.CaT),
			GdT:   calculateBitSize(assignment.GdT),
			VaT:   calculateBitSize(assignment.VaT),
			GcaAT: calculateBitSize(assignment.GcaAT),
			CidT:  calculateBitSize(assignment.CidT),
			Id:    calculateBitSize(assignment.Id),
		}
		currentStats.Total = currentStats.CaT + currentStats.GdT + currentStats.VaT +
			currentStats.GcaAT + currentStats.CidT + currentStats.Id
		fmt.Printf("Current group variable bit size stats:\n")
		fmt.Printf("  CaT: %d bits\n", currentStats.CaT)
		fmt.Printf("  GdT: %d bits\n", currentStats.GdT)
		fmt.Printf("  VaT: %d bits\n", currentStats.VaT)
		fmt.Printf("  GcaAT: %d bits\n", currentStats.GcaAT)
		fmt.Printf("  CidT: %d bits\n", currentStats.CidT)
		fmt.Printf("  Id: %d bits\n", currentStats.Id)
		fmt.Printf("  Current group total bits: %d bits\n", currentStats.Total)
	}
	globalStats := BitSizeStats{
		CaT:   calculateBitSize(upc.CaTG),
		GdT:   calculateBitSize(upc.GdTG),
		VaT:   calculateBitSize(upc.VaTG),
		GcaAT: calculateBitSize(upc.CaATG),
		CidT:  calculateBitSize(upc.CidTG),
	}
	globalStats.Total = globalStats.CaT + globalStats.GdT + globalStats.VaT +
		globalStats.GcaAT + globalStats.CidT
	fmt.Printf("Total bits for %d issuers: %d bits\n", n, globalStats.Total)

	var upcircuit upCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &upcircuit)
	pk, vk, _ := groth16.Setup(ccs)

	witness, _ := frontend.NewWitness(&upc, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("invalid upProof")
	}
}
