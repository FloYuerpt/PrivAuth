package privauth

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// GenerateVerifierChallenge samples a random verifier challenge vector.
// Δ = (δ_1, ..., δ_n)
func GenerateVerifierChallenge(n int, q *big.Int) (*VerifierChallenge, error) {
	delta := make([]*big.Int, n)

	for i := 0; i < n; i++ {
		d, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}
		delta[i] = d
	}

	return &VerifierChallenge{Delta: delta}, nil
}

// BatchVer1Prove constructs a batch verification proof (attribute-hiding).
//
// Steps:
// 1) Verifier samples Δ=(δ_1,...,δ_n)
// 2) Prover samples k1, k2
// 3) Compute A=a^{k1·k2}, B=b^{k1}, σ=(Πσ_i^{δ_i})^{k1·k2}
// 4) Produce a ZK proof that X' = (ΠX_i^{w_i·δ_i})^{k2} is constructed correctly
// 5) Verifier checks: e(σ,g) = e(A,ΠX_i^{δ_i})·e(B,X')
func BatchVer1Prove(
	params *SystemParameters,
	credentials []*Credential,
	challenge *VerifierChallenge,
) (*BatchVerifyProof, error) {

	n := len(credentials)
	if n != len(challenge.Delta) {
		return nil, ErrInvalidBatchSize
	}

	// Sample k1, k2 ∈ Zq.
	k1, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}
	k2, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	// Compute a = H1(φ), b = H2(φ) in G1.
	a := Hash1(params.Phi)
	b := Hash2(params.Phi)

	// Compute k1·k2.
	k1k2 := new(big.Int).Mul(k1, k2)
	k1k2.Mod(k1k2, params.Q)

	// Construct A = a^{k1·k2} in G1.
	var aJac bn254.G1Jac
	aJac.FromAffine(&a)
	var AJac bn254.G1Jac
	AJac.ScalarMultiplication(&aJac, k1k2)
	var A bn254.G1Affine
	A.FromJacobian(&AJac)

	// Construct B = b^{k1} in G1.
	var bJac bn254.G1Jac
	bJac.FromAffine(&b)
	var BJac bn254.G1Jac
	BJac.ScalarMultiplication(&bJac, k1)
	var B bn254.G1Affine
	B.FromJacobian(&BJac)

	// Compute Πσ_i^{δ_i}.
	var prodSigma bn254.G1Jac
	prodSigma.Set(&bn254.G1Jac{}) // identity element

	for i := 0; i < n; i++ {
		var sigmaI bn254.G1Jac
		sigmaI.FromAffine(&credentials[i].Sigma)
		sigmaI.ScalarMultiplication(&sigmaI, challenge.Delta[i])
		prodSigma.AddAssign(&sigmaI)
	}

	// σ = (Πσ_i^{δ_i})^{k1·k2}
	prodSigma.ScalarMultiplication(&prodSigma, k1k2)
	var sigma bn254.G1Affine
	sigma.FromJacobian(&prodSigma)

	// Compute Σ(w_i·δ_i) for the ZK statement.
	sumWiDelta := new(big.Int).SetInt64(0)

	for i := 0; i < n; i++ {
		// w_i · δ_i
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)
		sumWiDelta.Add(sumWiDelta, wiDelta)
	}
	sumWiDelta.Mod(sumWiDelta, params.Q)

	// Compute X' = (ΠX_i^{w_i·δ_i})^{k2} in G2.
	var prodX bn254.G2Jac
	prodX.Set(&bn254.G2Jac{}) // identity element

	for i := 0; i < n; i++ {
		// w_i · δ_i
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)

		// X_i^{w_i·δ_i} (IssuerPK is in G2).
		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, wiDelta)
		prodX.AddAssign(&Xi)
	}

	// X' = (ΠX_i^{w_i·δ_i})^{k2}
	prodX.ScalarMultiplication(&prodX, k2)
	var XPrime bn254.G2Affine
	XPrime.FromJacobian(&prodX)

	// ========== Groth16 ZK proof ==========

	// Check batch size.
	if n > MaxBatchSize {
		return nil, ErrInvalidBatchSize
	}

	// 1) Compile circuit (for simplicity compiled every time here).
	var circuitTemplate BatchVer1Circuit
	// Initialize arrays to zero.
	for i := 0; i < MaxBatchSize; i++ {
		circuitTemplate.Delta[i] = 0
		circuitTemplate.Weights[i] = 0
		circuitTemplate.IDs[i] = 0
		circuitTemplate.Attrs[i] = 0
		circuitTemplate.Active[i] = 0
	}
	circuitTemplate.SumWiDelta = 0
	circuitTemplate.Phi = 0
	circuitTemplate.EnforceWiCheck = 0
	circuitTemplate.K2 = 0

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitTemplate)
	if err != nil {
		return nil, err
	}

	// 2) Setup - generate proving and verifying keys.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}

	// 3) Build witness.
	var assignment BatchVer1Circuit
	assignment.SumWiDelta = sumWiDelta
	assignment.Phi = params.Phi
	assignment.EnforceWiCheck = 1 // enable check
	assignment.K2 = k2

	// Fill first n elements; the rest stays 0.
	for i := 0; i < n; i++ {
		assignment.Delta[i] = challenge.Delta[i]
		assignment.Weights[i] = credentials[i].Wi
		// Pack ID/attributes into field elements (simple bytes-to-int mapping).
		assignment.IDs[i] = new(big.Int).SetBytes(credentials[i].Identity)
		assignment.Attrs[i] = new(big.Int).SetBytes(credentials[i].Attributes)
		assignment.Active[i] = 1
	}
	// For unused slots: IDs=0, Attrs=0, but Weights must match Hash3(0,0,phi) to satisfy enforced checks.
	zeroWi := Hash3(nil, nil, params.Phi)
	for i := n; i < MaxBatchSize; i++ {
		assignment.Delta[i] = 0
		assignment.Weights[i] = zeroWi
		assignment.IDs[i] = 0
		assignment.Attrs[i] = 0
		assignment.Active[i] = 0
	}

	// 4) Create witness.
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// 5) Prove (Groth16).
	groth16Proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, err
	}

	// 6) Extract public witness.
	publicWitness, err := witness.Public()
	if err != nil {
		return nil, err
	}

	// ========== Assemble proof ==========

	proof := &BatchVerifyProof{
		A:             A,
		B:             B,
		Sigma:         sigma,
		XPrime:        XPrime,
		K1:            nil,           // do not reveal k1
		K2:            nil,           // do not reveal k2
		Groth16Proof:  groth16Proof,  // Groth16 proof
		VerifyingKey:  vk,            // Verification key
		PublicWitness: publicWitness, // Public witness
		ZKProof:       nil,           // legacy unused
	}

	return proof, nil
}

// BatchVer1Verify verifies the BatchVer1 proof.
// It checks: e(σ,g) = e(A,ΠX_i^{δ_i})·e(B,X') and also verifies the Groth16 proof.
func BatchVer1Verify(
	params *SystemParameters,
	credentials []*Credential,
	challenge *VerifierChallenge,
	proof *BatchVerifyProof,
) bool {

	n := len(credentials)
	if n != len(challenge.Delta) {
		return false
	}

	// Basic proof sanity checks.
	if proof == nil {
		return false
	}

	// ========== Step 1: verify Groth16 proof ==========

	// Ensure the proof contains a public witness.
	if proof.PublicWitness == nil {
		return false // missing public witness
	}

	// Verify Groth16 proof using embedded vk and public witness.
	err := groth16.Verify(proof.Groth16Proof, proof.VerifyingKey, proof.PublicWitness)
	if err != nil {
		return false
	}

	// ========== Step 2: verify pairing equation ==========
	// Get G2 generator.
	_, g2GenJac, _, _ := bn254.Generators()
	var g2Gen bn254.G2Affine
	g2Gen.FromJacobian(&g2GenJac)

	// Compute ΠX_i^{δ_i} in G2.
	var prodXDelta bn254.G2Jac
	prodXDelta.Set(&bn254.G2Jac{}) // identity element

	for i := 0; i < n; i++ {
		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, challenge.Delta[i])
		prodXDelta.AddAssign(&Xi)
	}

	var prodXDeltaAffine bn254.G2Affine
	prodXDeltaAffine.FromJacobian(&prodXDelta)

	// Compute e(σ, g2).
	leftPairing, err := bn254.Pair(
		[]bn254.G1Affine{proof.Sigma},
		[]bn254.G2Affine{g2Gen},
	)
	if err != nil {
		return false
	}

	// Compute e(A, ΠX_i^{δ_i}).
	pairing1, err := bn254.Pair(
		[]bn254.G1Affine{proof.A},
		[]bn254.G2Affine{prodXDeltaAffine},
	)
	if err != nil {
		return false
	}

	// Compute e(B, X').
	pairing2, err := bn254.Pair(
		[]bn254.G1Affine{proof.B},
		[]bn254.G2Affine{proof.XPrime},
	)
	if err != nil {
		return false
	}

	// right = e(A, ΠX_i^{δ_i}) · e(B, X')
	var rightPairing bn254.GT
	rightPairing.Mul(&pairing1, &pairing2)

	// Check left == right.
	pairingValid := leftPairing.Equal(&rightPairing)

	return pairingValid
}

// BatchVer2Prove constructs a batch verification proof (attribute-hiding + issuer-hiding).
//
// Steps:
// 1) Same as BatchVer1, but also hide issuer public keys inside the ZK statement
// 2) Prove X”=(ΠX_i^{δ_i})^{k2} and X'=(ΠX_i^{w_i·δ_i})^{k2} are constructed correctly
// 3) Check: e(σ,g) = e(A,X”)·e(B,X')
func BatchVer2Prove(
	params *SystemParameters,
	credentials []*Credential,
	challenge *VerifierChallenge,
) (*BatchVerifyProof2, error) {

	n := len(credentials)
	if n != len(challenge.Delta) {
		return nil, ErrInvalidBatchSize
	}

	// Sample k1, k2 ∈ Zq.
	k1, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}
	k2, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	// Compute a = H1(φ), b = H2(φ) in G1.
	a := Hash1(params.Phi)
	b := Hash2(params.Phi)

	// Compute k1·k2.
	k1k2 := new(big.Int).Mul(k1, k2)
	k1k2.Mod(k1k2, params.Q)

	// Construct A = a^{k1·k2} in G1.
	var aJac bn254.G1Jac
	aJac.FromAffine(&a)
	var AJac bn254.G1Jac
	AJac.ScalarMultiplication(&aJac, k1k2)
	var A bn254.G1Affine
	A.FromJacobian(&AJac)

	// Construct B = b^{k1} in G1.
	var bJac bn254.G1Jac
	bJac.FromAffine(&b)
	var BJac bn254.G1Jac
	BJac.ScalarMultiplication(&bJac, k1)
	var B bn254.G1Affine
	B.FromJacobian(&BJac)

	// Compute σ = (Πσ_i^{δ_i})^{k1·k2}.
	var prodSigma bn254.G1Jac
	prodSigma.Set(&bn254.G1Jac{})

	for i := 0; i < n; i++ {
		var sigmaI bn254.G1Jac
		sigmaI.FromAffine(&credentials[i].Sigma)
		sigmaI.ScalarMultiplication(&sigmaI, challenge.Delta[i])
		prodSigma.AddAssign(&sigmaI)
	}

	prodSigma.ScalarMultiplication(&prodSigma, k1k2)
	var sigma bn254.G1Affine
	sigma.FromJacobian(&prodSigma)

	// Compute X'' = ΠX_i^{δ_i} in G2 (no k2 multiplication; A already includes k2).
	var prodX2 bn254.G2Jac
	prodX2.Set(&bn254.G2Jac{})

	for i := 0; i < n; i++ {
		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, challenge.Delta[i])
		prodX2.AddAssign(&Xi)
	}

	// Note: no k2 multiplication here because in the pairing equation A = a^{k1·k2} already includes it.
	var XPrime2 bn254.G2Affine
	XPrime2.FromJacobian(&prodX2)

	// Compute X' = (ΠX_i^{w_i·δ_i})^{k2} in G2.
	var prodX bn254.G2Jac
	prodX.Set(&bn254.G2Jac{})

	for i := 0; i < n; i++ {
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)

		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, wiDelta)
		prodX.AddAssign(&Xi)
	}

	prodX.ScalarMultiplication(&prodX, k2)
	var XPrime bn254.G2Affine
	XPrime.FromJacobian(&prodX)

	// Groth16 ZK proof (BatchVer2Circuit).
	// The circuit checks Σ(w_i·δ_i) and enforces w_i = H3(ID_i || m_i || φ).
	if n > MaxBatchSize {
		return nil, ErrInvalidBatchSize
	}

	// 1) Compile circuit.
	var circuitTemplate BatchVer2Circuit
	for i := 0; i < MaxBatchSize; i++ {
		circuitTemplate.Delta[i] = 0
		circuitTemplate.Weights[i] = 0
		circuitTemplate.IssuerPKs[i] = 0
		circuitTemplate.IDs[i] = 0
		circuitTemplate.Attrs[i] = 0
		circuitTemplate.Active[i] = 0
	}
	circuitTemplate.SumWiDelta = 0
	circuitTemplate.SumXiDelta = 0
	circuitTemplate.SumXiWiDelta = 0
	circuitTemplate.Phi = 0
	circuitTemplate.EnforceWiCheck = 0
	circuitTemplate.K2 = 0

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitTemplate)
	if err != nil {
		return nil, err
	}

	// 2. Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}

	// 3) Build witness: compute required sums.
	sumWiDelta := new(big.Int).SetInt64(0)
	sumXiDelta := new(big.Int).SetInt64(0)
	sumXiWiDelta := new(big.Int).SetInt64(0)

	// Encode IssuerPK (a G2 point) as a scalar for circuit input.
	issuerPKScalars := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pkBytes := credentials[i].IssuerPK.Bytes()
		issuerPKScalars[i] = new(big.Int).SetBytes(pkBytes[:32]) // take first 32 bytes
		issuerPKScalars[i].Mod(issuerPKScalars[i], params.Q)
	}

	// Compute all three sums.
	for i := 0; i < n; i++ {
		// Σ(w_i · δ_i)
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)
		sumWiDelta.Add(sumWiDelta, wiDelta)

		// Σ(X_i · δ_i)
		xiDelta := new(big.Int).Mul(issuerPKScalars[i], challenge.Delta[i])
		xiDelta.Mod(xiDelta, params.Q)
		sumXiDelta.Add(sumXiDelta, xiDelta)

		// Σ(X_i · w_i · δ_i)
		xiWi := new(big.Int).Mul(issuerPKScalars[i], credentials[i].Wi)
		xiWi.Mod(xiWi, params.Q)
		xiWiDelta := new(big.Int).Mul(xiWi, challenge.Delta[i])
		xiWiDelta.Mod(xiWiDelta, params.Q)
		sumXiWiDelta.Add(sumXiWiDelta, xiWiDelta)
	}
	sumWiDelta.Mod(sumWiDelta, params.Q)
	sumXiDelta.Mod(sumXiDelta, params.Q)
	sumXiWiDelta.Mod(sumXiWiDelta, params.Q)

	// 4) Fill circuit assignment.
	var assignment BatchVer2Circuit
	assignment.SumWiDelta = sumWiDelta
	assignment.SumXiDelta = sumXiDelta
	assignment.SumXiWiDelta = sumXiWiDelta
	assignment.Phi = params.Phi
	assignment.EnforceWiCheck = 1
	assignment.K2 = k2

	for i := 0; i < n; i++ {
		assignment.Delta[i] = challenge.Delta[i]
		assignment.Weights[i] = credentials[i].Wi
		assignment.IssuerPKs[i] = issuerPKScalars[i]
		assignment.IDs[i] = new(big.Int).SetBytes(credentials[i].Identity)
		assignment.Attrs[i] = new(big.Int).SetBytes(credentials[i].Attributes)
		assignment.Active[i] = 1
	}

	// Unused slots: set to consistent values.
	zeroWi := Hash3(nil, nil, params.Phi)
	zeroIssuerPK := big.NewInt(0)
	for i := n; i < MaxBatchSize; i++ {
		assignment.Delta[i] = 0
		assignment.Weights[i] = zeroWi
		assignment.IssuerPKs[i] = zeroIssuerPK
		assignment.IDs[i] = 0
		assignment.Attrs[i] = 0
		assignment.Active[i] = 0
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	prf, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return nil, err
	}
	pubW, err := w.Public()
	if err != nil {
		return nil, err
	}

	proof := &BatchVerifyProof2{
		A:             A,
		B:             B,
		Sigma:         sigma,
		XPrime:        XPrime,
		XPrime2:       XPrime2,
		K1:            k1,
		K2:            k2,
		Groth16Proof:  prf,
		VerifyingKey:  vk,
		PublicWitness: pubW,
		ZKProof:       nil,
	}

	return proof, nil
}

// BatchVer2Verify verifies the BatchVer2 proof (issuer-hidden).
// It checks: e(σ,g) = e(A,X”)·e(B,X').
func BatchVer2Verify(
	params *SystemParameters,
	proof *BatchVerifyProof2,
) bool {

	// Step 1: verify Groth16 proof (using embedded vk and public witness).
	if proof == nil || proof.PublicWitness == nil {
		return false
	}
	if err := groth16.Verify(proof.Groth16Proof, proof.VerifyingKey, proof.PublicWitness); err != nil {
		return false
	}

	// Get G2 generator.
	_, g2GenJac, _, _ := bn254.Generators()
	var g2Gen bn254.G2Affine
	g2Gen.FromJacobian(&g2GenJac)

	// Compute e(σ, g2).
	leftPairing, err := bn254.Pair(
		[]bn254.G1Affine{proof.Sigma},
		[]bn254.G2Affine{g2Gen},
	)
	if err != nil {
		return false
	}

	// Compute e(A, X'').
	pairing1, err := bn254.Pair(
		[]bn254.G1Affine{proof.A},
		[]bn254.G2Affine{proof.XPrime2},
	)
	if err != nil {
		return false
	}

	// Compute e(B, X').
	pairing2, err := bn254.Pair(
		[]bn254.G1Affine{proof.B},
		[]bn254.G2Affine{proof.XPrime},
	)
	if err != nil {
		return false
	}

	// right = e(A, X'') · e(B, X')
	var rightPairing bn254.GT
	rightPairing.Mul(&pairing1, &pairing2)

	// Check left == right.
	return leftPairing.Equal(&rightPairing)
}

// BatchVer3Prove constructs the BatchVer3 proof (all verification logic in-circuit).
// The verifier only checks the Groth16 proof (no pairing computation required).
func BatchVer3Prove(
	params *SystemParameters,
	credentials []*Credential,
	challenge *VerifierChallenge,
) (*BatchVerifyProof, error) {

	n := len(credentials)
	if n != len(challenge.Delta) {
		return nil, ErrInvalidBatchSize
	}

	// Sample k1, k2 ∈ Zq.
	k1, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}
	k2, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	// Compute a = H1(φ), b = H2(φ) in G1.
	a := Hash1(params.Phi)
	b := Hash2(params.Phi)

	// Compute k1·k2.
	k1k2 := new(big.Int).Mul(k1, k2)
	k1k2.Mod(k1k2, params.Q)

	// Construct A = a^{k1·k2} in G1.
	var aJac bn254.G1Jac
	aJac.FromAffine(&a)
	var AJac bn254.G1Jac
	AJac.ScalarMultiplication(&aJac, k1k2)
	var A bn254.G1Affine
	A.FromJacobian(&AJac)

	// Construct B = b^{k1} in G1.
	var bJac bn254.G1Jac
	bJac.FromAffine(&b)
	var BJac bn254.G1Jac
	BJac.ScalarMultiplication(&bJac, k1)
	var B bn254.G1Affine
	B.FromJacobian(&BJac)

	// Compute Πσ_i^{δ_i}.
	var prodSigma bn254.G1Jac
	prodSigma.Set(&bn254.G1Jac{})

	for i := 0; i < n; i++ {
		var sigmaI bn254.G1Jac
		sigmaI.FromAffine(&credentials[i].Sigma)
		sigmaI.ScalarMultiplication(&sigmaI, challenge.Delta[i])
		prodSigma.AddAssign(&sigmaI)
	}

	// σ = (Πσ_i^{δ_i})^{k1·k2}
	prodSigma.ScalarMultiplication(&prodSigma, k1k2)
	var sigma bn254.G1Affine
	sigma.FromJacobian(&prodSigma)

	// Compute X' = (ΠX_i^{w_i·δ_i})^{k2} in G2.
	var prodX bn254.G2Jac
	prodX.Set(&bn254.G2Jac{})

	for i := 0; i < n; i++ {
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)

		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, wiDelta)
		prodX.AddAssign(&Xi)
	}

	prodX.ScalarMultiplication(&prodX, k2)
	var XPrime bn254.G2Affine
	XPrime.FromJacobian(&prodX)

	// ========== Groth16 ZK proof (BatchVer3Circuit) ==========

	if n > MaxBatchSize {
		return nil, ErrInvalidBatchSize
	}

	// 1) Compile circuit.
	var circuitTemplate BatchVer3Circuit
	for i := 0; i < MaxBatchSize; i++ {
		circuitTemplate.Delta[i] = 0
		circuitTemplate.Weights[i] = 0
		circuitTemplate.IssuerPKs[i] = 0
		circuitTemplate.IDs[i] = 0
		circuitTemplate.Attrs[i] = 0
		circuitTemplate.Active[i] = 0
	}
	circuitTemplate.SumWiDelta = 0
	circuitTemplate.SumXiDelta = 0
	circuitTemplate.SumXiWiDelta = 0
	circuitTemplate.Phi = 0
	circuitTemplate.EnforceWiCheck = 0
	circuitTemplate.K1 = 0
	circuitTemplate.K2 = 0

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitTemplate)
	if err != nil {
		return nil, err
	}

	// 2. Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}

	// 3) Build witness: compute required sums.
	sumWiDelta := new(big.Int).SetInt64(0)
	sumXiDelta := new(big.Int).SetInt64(0)
	sumXiWiDelta := new(big.Int).SetInt64(0)

	// Encode IssuerPK (a G2 point) as a scalar for circuit input.
	issuerPKScalars := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pkBytes := credentials[i].IssuerPK.Bytes()
		issuerPKScalars[i] = new(big.Int).SetBytes(pkBytes[:32])
		issuerPKScalars[i].Mod(issuerPKScalars[i], params.Q)
	}

	// Compute all three sums.
	for i := 0; i < n; i++ {
		// Σ(w_i · δ_i)
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)
		sumWiDelta.Add(sumWiDelta, wiDelta)

		// Σ(X_i · δ_i)
		xiDelta := new(big.Int).Mul(issuerPKScalars[i], challenge.Delta[i])
		xiDelta.Mod(xiDelta, params.Q)
		sumXiDelta.Add(sumXiDelta, xiDelta)

		// Σ(X_i · w_i · δ_i)
		xiWi := new(big.Int).Mul(issuerPKScalars[i], credentials[i].Wi)
		xiWi.Mod(xiWi, params.Q)
		xiWiDelta := new(big.Int).Mul(xiWi, challenge.Delta[i])
		xiWiDelta.Mod(xiWiDelta, params.Q)
		sumXiWiDelta.Add(sumXiWiDelta, xiWiDelta)
	}
	sumWiDelta.Mod(sumWiDelta, params.Q)
	sumXiDelta.Mod(sumXiDelta, params.Q)
	sumXiWiDelta.Mod(sumXiWiDelta, params.Q)

	// 4) Fill circuit assignment.
	var assignment BatchVer3Circuit
	assignment.SumWiDelta = sumWiDelta
	assignment.SumXiDelta = sumXiDelta
	assignment.SumXiWiDelta = sumXiWiDelta
	assignment.Phi = params.Phi
	assignment.EnforceWiCheck = 1
	assignment.K1 = k1
	assignment.K2 = k2

	for i := 0; i < n; i++ {
		assignment.Delta[i] = challenge.Delta[i]
		assignment.Weights[i] = credentials[i].Wi
		assignment.IssuerPKs[i] = issuerPKScalars[i]
		assignment.IDs[i] = new(big.Int).SetBytes(credentials[i].Identity)
		assignment.Attrs[i] = new(big.Int).SetBytes(credentials[i].Attributes)
		assignment.Active[i] = 1
	}

	// Unused slots: set to consistent values.
	zeroWi := Hash3(nil, nil, params.Phi)
	zeroIssuerPK := big.NewInt(0)
	for i := n; i < MaxBatchSize; i++ {
		assignment.Delta[i] = 0
		assignment.Weights[i] = zeroWi
		assignment.IssuerPKs[i] = zeroIssuerPK
		assignment.IDs[i] = 0
		assignment.Attrs[i] = 0
		assignment.Active[i] = 0
	}

	// 5) Create witness.
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// 6) Prove (Groth16).
	groth16Proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, err
	}

	// 7) Extract public witness.
	publicWitness, err := witness.Public()
	if err != nil {
		return nil, err
	}

	// ========== Assemble proof ==========

	proof := &BatchVerifyProof{
		A:             A,
		B:             B,
		Sigma:         sigma,
		XPrime:        XPrime,
		K1:            nil,
		K2:            nil,
		Groth16Proof:  groth16Proof,
		VerifyingKey:  vk,
		PublicWitness: publicWitness,
		ZKProof:       nil,
	}

	return proof, nil
}

// BatchVer3Verify verifies the BatchVer3 proof.
// The verifier only checks the Groth16 proof (no pairing computation required).
func BatchVer3Verify(
	params *SystemParameters,
	proof *BatchVerifyProof,
) bool {

	// Basic proof sanity checks.
	if proof == nil || proof.PublicWitness == nil {
		return false
	}

	// Verify Groth16 proof only.
	err := groth16.Verify(proof.Groth16Proof, proof.VerifyingKey, proof.PublicWitness)
	if err != nil {
		return false
	}

	// BatchVer3: all verification logic is inside the circuit.
	return true
}

// BatchVer4Prove constructs the BatchVer4 proof (fully-ZK BatchVer2).
// All verification logic is moved into the circuit, including w_i checks and pairing-equation checks.
// The verifier only checks the Groth16 proof (no pairing computation required).
func BatchVer4Prove(
	params *SystemParameters,
	credentials []*Credential,
	challenge *VerifierChallenge,
) (*BatchVerifyProof2, error) {

	n := len(credentials)
	if n != len(challenge.Delta) {
		return nil, ErrInvalidBatchSize
	}

	// Sample k1, k2 ∈ Zq.
	k1, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}
	k2, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	// Compute a = H1(φ), b = H2(φ) in G1.
	a := Hash1(params.Phi)
	b := Hash2(params.Phi)

	// Compute k1·k2.
	k1k2 := new(big.Int).Mul(k1, k2)
	k1k2.Mod(k1k2, params.Q)

	// Construct A = a^{k1·k2} in G1.
	var aJac bn254.G1Jac
	aJac.FromAffine(&a)
	var AJac bn254.G1Jac
	AJac.ScalarMultiplication(&aJac, k1k2)
	var A bn254.G1Affine
	A.FromJacobian(&AJac)

	// Construct B = b^{k1} in G1.
	var bJac bn254.G1Jac
	bJac.FromAffine(&b)
	var BJac bn254.G1Jac
	BJac.ScalarMultiplication(&bJac, k1)
	var B bn254.G1Affine
	B.FromJacobian(&BJac)

	// Compute σ = (Πσ_i^{δ_i})^{k1·k2}.
	var prodSigma bn254.G1Jac
	prodSigma.Set(&bn254.G1Jac{})

	for i := 0; i < n; i++ {
		var sigmaI bn254.G1Jac
		sigmaI.FromAffine(&credentials[i].Sigma)
		sigmaI.ScalarMultiplication(&sigmaI, challenge.Delta[i])
		prodSigma.AddAssign(&sigmaI)
	}

	prodSigma.ScalarMultiplication(&prodSigma, k1k2)
	var sigma bn254.G1Affine
	sigma.FromJacobian(&prodSigma)

	// Compute X'' = ΠX_i^{δ_i} in G2 (no k2 multiplication).
	var prodX2 bn254.G2Jac
	prodX2.Set(&bn254.G2Jac{})

	for i := 0; i < n; i++ {
		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, challenge.Delta[i])
		prodX2.AddAssign(&Xi)
	}

	var XPrime2 bn254.G2Affine
	XPrime2.FromJacobian(&prodX2)

	// Compute X' = (ΠX_i^{w_i·δ_i})^{k2} in G2.
	var prodX bn254.G2Jac
	prodX.Set(&bn254.G2Jac{})

	for i := 0; i < n; i++ {
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)

		var Xi bn254.G2Jac
		Xi.FromAffine(&credentials[i].IssuerPK)
		Xi.ScalarMultiplication(&Xi, wiDelta)
		prodX.AddAssign(&Xi)
	}

	prodX.ScalarMultiplication(&prodX, k2)
	var XPrime bn254.G2Affine
	XPrime.FromJacobian(&prodX)

	// ========== Groth16 ZK proof (BatchVer4Circuit) ==========

	if n > MaxBatchSize {
		return nil, ErrInvalidBatchSize
	}

	// 1) Compile circuit.
	var circuitTemplate BatchVer4Circuit
	for i := 0; i < MaxBatchSize; i++ {
		circuitTemplate.Delta[i] = 0
		circuitTemplate.Weights[i] = 0
		circuitTemplate.IssuerPKs[i] = 0
		circuitTemplate.IDs[i] = 0
		circuitTemplate.Attrs[i] = 0
		circuitTemplate.Active[i] = 0
	}
	circuitTemplate.SumWiDelta = 0
	circuitTemplate.SumXiDelta = 0
	circuitTemplate.SumXiWiDelta = 0
	circuitTemplate.Phi = 0
	circuitTemplate.EnforceWiCheck = 0
	circuitTemplate.K1 = 0
	circuitTemplate.K2 = 0

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitTemplate)
	if err != nil {
		return nil, err
	}

	// 2. Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}

	// 3) Build witness: compute required sums.
	sumWiDelta := new(big.Int).SetInt64(0)
	sumXiDelta := new(big.Int).SetInt64(0)
	sumXiWiDelta := new(big.Int).SetInt64(0)

	// Encode IssuerPK (a G2 point) as a scalar for circuit input.
	issuerPKScalars := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pkBytes := credentials[i].IssuerPK.Bytes()
		issuerPKScalars[i] = new(big.Int).SetBytes(pkBytes[:32])
		issuerPKScalars[i].Mod(issuerPKScalars[i], params.Q)
	}

	// Compute all three sums.
	for i := 0; i < n; i++ {
		// Σ(w_i · δ_i)
		wiDelta := new(big.Int).Mul(credentials[i].Wi, challenge.Delta[i])
		wiDelta.Mod(wiDelta, params.Q)
		sumWiDelta.Add(sumWiDelta, wiDelta)

		// Σ(X_i · δ_i)
		xiDelta := new(big.Int).Mul(issuerPKScalars[i], challenge.Delta[i])
		xiDelta.Mod(xiDelta, params.Q)
		sumXiDelta.Add(sumXiDelta, xiDelta)

		// Σ(X_i · w_i · δ_i)
		xiWi := new(big.Int).Mul(issuerPKScalars[i], credentials[i].Wi)
		xiWi.Mod(xiWi, params.Q)
		xiWiDelta := new(big.Int).Mul(xiWi, challenge.Delta[i])
		xiWiDelta.Mod(xiWiDelta, params.Q)
		sumXiWiDelta.Add(sumXiWiDelta, xiWiDelta)
	}
	sumWiDelta.Mod(sumWiDelta, params.Q)
	sumXiDelta.Mod(sumXiDelta, params.Q)
	sumXiWiDelta.Mod(sumXiWiDelta, params.Q)

	// 4) Fill circuit assignment.
	var assignment BatchVer4Circuit
	assignment.SumWiDelta = sumWiDelta
	assignment.SumXiDelta = sumXiDelta
	assignment.SumXiWiDelta = sumXiWiDelta
	assignment.Phi = params.Phi
	assignment.EnforceWiCheck = 1
	assignment.K1 = k1
	assignment.K2 = k2

	for i := 0; i < n; i++ {
		assignment.Delta[i] = challenge.Delta[i]
		assignment.Weights[i] = credentials[i].Wi
		assignment.IssuerPKs[i] = issuerPKScalars[i]
		assignment.IDs[i] = new(big.Int).SetBytes(credentials[i].Identity)
		assignment.Attrs[i] = new(big.Int).SetBytes(credentials[i].Attributes)
		assignment.Active[i] = 1
	}

	// Unused slots: set to consistent values.
	zeroWi := Hash3(nil, nil, params.Phi)
	zeroIssuerPK := big.NewInt(0)
	for i := n; i < MaxBatchSize; i++ {
		assignment.Delta[i] = 0
		assignment.Weights[i] = zeroWi
		assignment.IssuerPKs[i] = zeroIssuerPK
		assignment.IDs[i] = 0
		assignment.Attrs[i] = 0
		assignment.Active[i] = 0
	}

	// 5) Create witness.
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// 6) Prove (Groth16).
	groth16Proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, err
	}

	// 7) Extract public witness.
	publicWitness, err := witness.Public()
	if err != nil {
		return nil, err
	}

	// ========== Assemble proof ==========

	proof := &BatchVerifyProof2{
		A:             A,
		B:             B,
		Sigma:         sigma,
		XPrime:        XPrime,
		XPrime2:       XPrime2,
		K1:            nil, // do not reveal k1
		K2:            nil, // do not reveal k2
		Groth16Proof:  groth16Proof,
		VerifyingKey:  vk,
		PublicWitness: publicWitness,
		ZKProof:       nil,
	}

	return proof, nil
}

// BatchVer4Verify verifies the BatchVer4 proof.
// The verifier only checks the Groth16 proof (no pairing computation required).
func BatchVer4Verify(
	params *SystemParameters,
	proof *BatchVerifyProof2,
) bool {

	// Basic proof sanity checks.
	if proof == nil || proof.PublicWitness == nil {
		return false
	}

	// Verify Groth16 proof only.
	err := groth16.Verify(proof.Groth16Proof, proof.VerifyingKey, proof.PublicWitness)
	if err != nil {
		return false
	}

	// BatchVer4: all verification logic (including w_i checks) is inside the circuit.
	return true
}
