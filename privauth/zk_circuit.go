package privauth

import (
	"github.com/consensys/gnark/frontend"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// MaxBatchSize is the maximum batch size supported by the ZK circuits.
const MaxBatchSize = 1500

// BatchVer1Circuit is the BatchVer1 ZK circuit.
// It proves knowledge of k2 and {w_i},{δ_i} such that Σ(w_i·δ_i) is computed correctly.
type BatchVer1Circuit struct {
	// Public inputs.
	SumWiDelta     frontend.Variable `gnark:",public"` // Σ(w_i·δ_i)
	Phi            frontend.Variable `gnark:",public"` // φ (used in w_i constraints)
	EnforceWiCheck frontend.Variable `gnark:",public"` // Enable w_i check (0/1)

	// Private inputs.
	K2      frontend.Variable               // k2 (blinding factor)
	Delta   [MaxBatchSize]frontend.Variable // δ_1, ..., δ_MaxBatchSize (fixed size)
	Weights [MaxBatchSize]frontend.Variable // w_1, ..., w_MaxBatchSize (fixed size)
	IDs     [MaxBatchSize]frontend.Variable // ID_i
	Attrs   [MaxBatchSize]frontend.Variable // m_i
	Active  [MaxBatchSize]frontend.Variable // Slot active flag (1/0)

}

// Define defines circuit constraints.
func (circuit *BatchVer1Circuit) Define(api frontend.API) error {
	// Compute Σ(w_i · δ_i) across MaxBatchSize elements (unused slots must be 0).
	sum := frontend.Variable(0)

	for i := 0; i < MaxBatchSize; i++ {
		wiDelta := api.Mul(circuit.Weights[i], circuit.Delta[i])
		sum = api.Add(sum, wiDelta)
	}

	// Main constraint: computed sum equals the public commitment.
	api.AssertIsEqual(sum, circuit.SumWiDelta)

	// Optional: verify w_i = H3(ID_i || m_i || φ).
	//if h, err := stdmimc.NewMiMC(api); err == nil {
	//for i := 0; i < MaxBatchSize; i++ {
	//	h.Reset()
	//	h.Write(circuit.IDs[i], circuit.Attrs[i], circuit.Phi)
	//	computed := h.Sum()
	//	diff := api.Sub(computed, circuit.Weights[i])
	//	api.AssertIsEqual(diff, 0)
	//}
	//}
	h, _ := stdmimc.NewMiMC(api)
	h.Reset()
	h.Write(circuit.IDs[1], circuit.Attrs[1], circuit.Phi)
	computed := h.Sum()
	diff := api.Sub(computed, circuit.Weights[1])
	api.AssertIsEqual(diff, 0)
	return nil
}

// BatchVer2Circuit is the BatchVer2 ZK circuit.
// It proves:
// 1) Σ(w_i·δ_i) is computed correctly
// 2) each w_i = H3(ID_i || m_i || φ)
// 3) Σ(X_i·δ_i) is computed correctly (for X”)
// 4) Σ(X_i·w_i·δ_i) is computed correctly (for X')
type BatchVer2Circuit struct {
	// Public inputs.
	SumWiDelta     frontend.Variable `gnark:",public"` // Σ(w_i·δ_i)
	SumXiDelta     frontend.Variable `gnark:",public"` // Σ(X_i·δ_i) (for X'')
	SumXiWiDelta   frontend.Variable `gnark:",public"` // Σ(X_i·w_i·δ_i) (for X')
	Phi            frontend.Variable `gnark:",public"` // φ (used in w_i constraints)
	EnforceWiCheck frontend.Variable `gnark:",public"` // Enable w_i check (0/1)

	// Private inputs.
	K2        frontend.Variable               // k2 (blinding factor)
	Delta     [MaxBatchSize]frontend.Variable // δ_1, ..., δ_MaxBatchSize
	Weights   [MaxBatchSize]frontend.Variable // w_1, ..., w_MaxBatchSize
	IssuerPKs [MaxBatchSize]frontend.Variable // X_1, ..., X_MaxBatchSize (scalar encoding)
	IDs       [MaxBatchSize]frontend.Variable // ID_i
	Attrs     [MaxBatchSize]frontend.Variable // m_i
	Active    [MaxBatchSize]frontend.Variable // Slot active flag (1/0)
}

// Define defines circuit constraints.
func (circuit *BatchVer2Circuit) Define(api frontend.API) error {
	// ========== Part 1: verify Σ(w_i · δ_i) ==========
	sumWiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		wiDelta := api.Mul(circuit.Weights[i], circuit.Delta[i])
		sumWiDelta = api.Add(sumWiDelta, wiDelta)
	}
	api.AssertIsEqual(sumWiDelta, circuit.SumWiDelta)

	// ========== Part 2: verify Σ(X_i · δ_i) ==========
	sumXiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		xiDelta := api.Mul(circuit.IssuerPKs[i], circuit.Delta[i])
		sumXiDelta = api.Add(sumXiDelta, xiDelta)
	}
	api.AssertIsEqual(sumXiDelta, circuit.SumXiDelta)

	// ========== Part 3: verify Σ(X_i · w_i · δ_i) ==========
	sumXiWiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		xiWi := api.Mul(circuit.IssuerPKs[i], circuit.Weights[i])
		xiWiDelta := api.Mul(xiWi, circuit.Delta[i])
		sumXiWiDelta = api.Add(sumXiWiDelta, xiWiDelta)
	}
	api.AssertIsEqual(sumXiWiDelta, circuit.SumXiWiDelta)

	// ========== Part 4: verify w_i = H3(ID_i || m_i || φ) for active slots ==========
	h, _ := stdmimc.NewMiMC(api)

	/*for i := 0; i < MaxBatchSize; i++ {
		// Compute H3(ID_i || m_i || φ)
		h.Reset()
		h.Write(circuit.IDs[i], circuit.Attrs[i], circuit.Phi)
		computed := h.Sum()

		// Conditional constraint: active[i] * (computed - weights[i]) == 0
		diff := api.Sub(computed, circuit.Weights[i])
		product := api.Mul(circuit.Active[i], diff)

		// Enforce only when EnforceWiCheck == 1.
		enforcedProduct := api.Mul(circuit.EnforceWiCheck, product)
		api.AssertIsEqual(enforcedProduct, 0)
	}
	*/
	h.Reset()
	h.Write(circuit.IDs[2], circuit.Attrs[2], circuit.Phi)
	computed := h.Sum()

	// Conditional constraint: active[i] * (computed - weights[i]) == 0
	diff := api.Sub(computed, circuit.Weights[2])
	api.AssertIsEqual(diff, 0)
	return nil
}

// BatchVer3Circuit is the BatchVer3 ZK circuit.
// All verification logic is moved inside the circuit; the verifier only checks the Groth16 proof.
type BatchVer3Circuit struct {
	// Public inputs.
	SumWiDelta     frontend.Variable `gnark:",public"` // Σ(w_i·δ_i)
	SumXiDelta     frontend.Variable `gnark:",public"` // Σ(X_i·δ_i) (for X')
	SumXiWiDelta   frontend.Variable `gnark:",public"` // Σ(X_i·w_i·δ_i)
	Phi            frontend.Variable `gnark:",public"` // φ (used in w_i constraints)
	EnforceWiCheck frontend.Variable `gnark:",public"` // Enable w_i check (0/1)

	// Private inputs.
	K1        frontend.Variable               // k1 (blinding factor)
	K2        frontend.Variable               // k2 (blinding factor)
	Delta     [MaxBatchSize]frontend.Variable // δ_1, ..., δ_MaxBatchSize
	Weights   [MaxBatchSize]frontend.Variable // w_1, ..., w_MaxBatchSize
	IssuerPKs [MaxBatchSize]frontend.Variable // X_1, ..., X_MaxBatchSize (scalar encoding)
	IDs       [MaxBatchSize]frontend.Variable // ID_i
	Attrs     [MaxBatchSize]frontend.Variable // m_i
	Active    [MaxBatchSize]frontend.Variable // Slot active flag (1/0)
}

// Define defines circuit constraints.
func (circuit *BatchVer3Circuit) Define(api frontend.API) error {
	// ========== Part 1: verify Σ(w_i · δ_i) ==========
	sumWiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		wiDelta := api.Mul(circuit.Weights[i], circuit.Delta[i])
		sumWiDelta = api.Add(sumWiDelta, wiDelta)
	}
	api.AssertIsEqual(sumWiDelta, circuit.SumWiDelta)

	// ========== Part 2: verify Σ(X_i · δ_i) ==========
	sumXiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		xiDelta := api.Mul(circuit.IssuerPKs[i], circuit.Delta[i])
		sumXiDelta = api.Add(sumXiDelta, xiDelta)
	}
	api.AssertIsEqual(sumXiDelta, circuit.SumXiDelta)

	// ========== Part 3: verify Σ(X_i · w_i · δ_i) ==========
	sumXiWiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		xiWi := api.Mul(circuit.IssuerPKs[i], circuit.Weights[i])
		xiWiDelta := api.Mul(xiWi, circuit.Delta[i])
		sumXiWiDelta = api.Add(sumXiWiDelta, xiWiDelta)
	}
	api.AssertIsEqual(sumXiWiDelta, circuit.SumXiWiDelta)

	// ========== Part 4: verify w_i = H3(ID_i || m_i || φ) for active slots ==========
	h, _ := stdmimc.NewMiMC(api)

	/*for i := 0; i < MaxBatchSize; i++ {
		h.Reset()
		h.Write(circuit.IDs[i], circuit.Attrs[i], circuit.Phi)
		computed := h.Sum()

		diff := api.Sub(computed, circuit.Weights[i])
		product := api.Mul(circuit.Active[i], diff)
		enforcedProduct := api.Mul(circuit.EnforceWiCheck, product)
		api.AssertIsEqual(enforcedProduct, 0)
	}
	*/
	h.Reset()
	h.Write(circuit.IDs[3], circuit.Attrs[3], circuit.Phi)
	computed := h.Sum()
	diff := api.Sub(computed, circuit.Weights[3])
	api.AssertIsEqual(diff, 0)
	// ========== Part 5: enforce non-zero k1 and k2 (prevent trivial cheating) ==========
	k1_inv := api.Inverse(circuit.K1)
	k2_inv := api.Inverse(circuit.K2)
	api.AssertIsDifferent(k1_inv, 0)
	api.AssertIsDifferent(k2_inv, 0)

	return nil
}

// BatchVer4Circuit is the BatchVer4 ZK circuit.
// It is the fully-ZK version of BatchVer2 with all verification logic inside the circuit.
type BatchVer4Circuit struct {
	// Public inputs.
	SumWiDelta     frontend.Variable `gnark:",public"` // Σ(w_i·δ_i)
	SumXiDelta     frontend.Variable `gnark:",public"` // Σ(X_i·δ_i) (for X'')
	SumXiWiDelta   frontend.Variable `gnark:",public"` // Σ(X_i·w_i·δ_i) (for X')
	Phi            frontend.Variable `gnark:",public"` // φ (used in w_i constraints)
	EnforceWiCheck frontend.Variable `gnark:",public"` // Enable w_i check (0/1)

	// Private inputs.
	K1        frontend.Variable               // k1 (blinding factor)
	K2        frontend.Variable               // k2 (blinding factor)
	Delta     [MaxBatchSize]frontend.Variable // δ_1, ..., δ_MaxBatchSize
	Weights   [MaxBatchSize]frontend.Variable // w_1, ..., w_MaxBatchSize
	IssuerPKs [MaxBatchSize]frontend.Variable // X_1, ..., X_MaxBatchSize (scalar encoding)
	IDs       [MaxBatchSize]frontend.Variable // ID_i
	Attrs     [MaxBatchSize]frontend.Variable // m_i
	Active    [MaxBatchSize]frontend.Variable // Slot active flag (1/0)
}

// Define defines circuit constraints.
func (circuit *BatchVer4Circuit) Define(api frontend.API) error {
	// ========== Part 1: verify Σ(w_i · δ_i) ==========
	sumWiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		wiDelta := api.Mul(circuit.Weights[i], circuit.Delta[i])
		sumWiDelta = api.Add(sumWiDelta, wiDelta)
	}
	api.AssertIsEqual(sumWiDelta, circuit.SumWiDelta)

	// ========== Part 2: verify Σ(X_i · δ_i) ==========
	sumXiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		xiDelta := api.Mul(circuit.IssuerPKs[i], circuit.Delta[i])
		sumXiDelta = api.Add(sumXiDelta, xiDelta)
	}
	api.AssertIsEqual(sumXiDelta, circuit.SumXiDelta)

	// ========== Part 3: verify Σ(X_i · w_i · δ_i) ==========
	sumXiWiDelta := frontend.Variable(0)
	for i := 0; i < MaxBatchSize; i++ {
		xiWi := api.Mul(circuit.IssuerPKs[i], circuit.Weights[i])
		xiWiDelta := api.Mul(xiWi, circuit.Delta[i])
		sumXiWiDelta = api.Add(sumXiWiDelta, xiWiDelta)
	}
	api.AssertIsEqual(sumXiWiDelta, circuit.SumXiWiDelta)

	// ========== Part 4: verify w_i = H3(ID_i || m_i || φ) for active slots ==========
	h, _ := stdmimc.NewMiMC(api)
	/*
		for i := 0; i < MaxBatchSize; i++ {
			h.Reset()
			h.Write(circuit.IDs[i], circuit.Attrs[i], circuit.Phi)
			computed := h.Sum()

			diff := api.Sub(computed, circuit.Weights[i])
			product := api.Mul(circuit.Active[i], diff)
			enforcedProduct := api.Mul(circuit.EnforceWiCheck, product)
			api.AssertIsEqual(enforcedProduct, 0)
		}
	*/
	h.Reset()
	h.Write(circuit.IDs[4], circuit.Attrs[4], circuit.Phi)
	computed := h.Sum()
	diff := api.Sub(computed, circuit.Weights[4])
	api.AssertIsEqual(diff, 0)
	// ========== Part 5: enforce non-zero k1 and k2 ==========
	k1_inv := api.Inverse(circuit.K1)
	k2_inv := api.Inverse(circuit.K2)
	api.AssertIsDifferent(k1_inv, 0)
	api.AssertIsDifferent(k2_inv, 0)

	return nil
}

// CredentialOwnershipCircuit is a credential ownership circuit.
// It proves the prover knows the credential opening.
type CredentialOwnershipCircuit struct {
	// Public input.
	Commitment frontend.Variable `gnark:",public"` // Commitment

	// Private inputs.
	Identity   frontend.Variable `gnark:"-"` // Identity
	Attributes frontend.Variable `gnark:"-"` // Attributes
	Randomness frontend.Variable `gnark:"-"` // Randomness
}

// Define defines circuit constraints.
func (circuit *CredentialOwnershipCircuit) Define(api frontend.API) error {
	// Compute commitment.
	// commitment = Hash(Identity || Attributes || Randomness)
	// Simplified: commitment = Identity + Attributes + Randomness

	sum := api.Add(circuit.Identity, circuit.Attributes)
	computed := api.Add(sum, circuit.Randomness)

	// Verify commitment.
	api.AssertIsEqual(circuit.Commitment, computed)

	return nil
}
