package main

import (
	"encoding/json"
	"fmt"
	"time"

	"privauth"
)

func main() {
	fmt.Println("=" + repeatStr("=", 70) + "=")
	fmt.Println("  PrivAuth - Pairing-based Multi-Attribute Batch Authentication Demo")
	fmt.Println("=" + repeatStr("=", 70) + "=")
	fmt.Println()

	// Demo 1: DisSign (credential issuance)
	fmt.Println("[Demo 1] DisSign - Credential Issuance")
	fmt.Println(repeatStr("-", 72))
	demoDisSign()

	fmt.Println()
	fmt.Println(repeatStr("=", 72))
	fmt.Println()

	// Demo 2: BatchVer1 (attribute-hiding batch verification)
	fmt.Println("[Demo 2] BatchVer1 - Batch Verification (Attribute-Hiding)")
	fmt.Println(repeatStr("-", 72))
	demoBatchVer1()

	fmt.Println()
	fmt.Println(repeatStr("=", 72))
	fmt.Println()

	// Demo 3: BatchVer2 (attribute-hiding + issuer-hiding batch verification)
	fmt.Println("[Demo 3] BatchVer2 - Batch Verification (Attribute-Hiding + Issuer-Hiding)")
	fmt.Println(repeatStr("-", 72))
	demoBatchVer2()

	fmt.Println()
	fmt.Println(repeatStr("=", 72))
	fmt.Println()

	// Demo 4: BatchVer3 (all verification logic in-circuit)
	fmt.Println("[Demo 4] BatchVer3 - In-Circuit Verification (Fully-ZK BatchVer1)")
	fmt.Println(repeatStr("-", 72))
	demoBatchVer3()

	fmt.Println()
	fmt.Println(repeatStr("=", 72))
	fmt.Println()

	// Demo 5: BatchVer4 (fully-ZK BatchVer2)
	fmt.Println("[Demo 5] BatchVer4 - Fully-ZK BatchVer2 (Fastest Verify + Issuer-Hiding)")
	fmt.Println(repeatStr("-", 72))
	demoBatchVer4()

	fmt.Println()
	fmt.Println(repeatStr("=", 72))
	fmt.Println("Demo completed!")
}

func demoDisSign() {
	start := time.Now()

	// 1. System setup
	fmt.Println("1. System setup...")
	params, err := privauth.Setup(30 * 24 * time.Hour)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   ✓ Group order q: %d bits\n", params.Q.BitLen())
	fmt.Printf("   ✓ Valid until: %v\n", time.Unix(params.Phi.Int64(), 0).Format("2006-01-02"))

	// 2. Issuer key pair
	fmt.Println("\n2. Generate issuer key pair...")
	issuerSK, issuerPK, _ := privauth.GenerateIssuerKeyPair(params)
	fmt.Println("   ✓ Issuer key pair generated")

	// 3. Supervisor key pair
	fmt.Println("\n3. Generate supervisor key pair...")
	supervisorKeys, _ := privauth.GenerateSupervisorKeyPair(params)
	fmt.Println("   ✓ Supervisor key pair generated")

	// 4. User identity
	fmt.Println("\n4. Generate user identity...")
	userID, _ := privauth.GenerateUserIdentity()
	fmt.Printf("   ✓ User ID: %x...\n", userID.ID[:8])

	// 5. User attributes
	fmt.Println("\n5. Define user attributes...")
	attributes := []byte("age:25,vip_level:2,region:CN,score:95")
	fmt.Printf("   ✓ Attributes: %s\n", string(attributes))

	// 6. Issue credential
	fmt.Println("\n6. Issuer issues credential...")
	credential, escrow, _ := privauth.DisSign(
		params,
		issuerSK,
		issuerPK,
		supervisorKeys,
		userID,
		attributes,
	)
	fmt.Println("   ✓ Signature σ_i = a^{x_i} · b^{x_i·w_i}")
	fmt.Printf("   ✓ Weight w_i: %d bits\n", credential.Wi.BitLen())
	fmt.Println("   ✓ Identity escrow ciphertext C_U = (r·G, r·pk_S + ID_U)")

	// 7. Verify credential
	fmt.Println("\n7. Verify credential...")
	valid := privauth.VerifyCredential(params, credential)
	if valid {
		fmt.Println("   ✓ Credential verified")
	} else {
		fmt.Println("   ✗ Credential verification failed")
	}

	_ = escrow

	fmt.Printf("\nElapsed: %v\n", time.Since(start))
}

func demoBatchVer1() {

	// System setup
	fmt.Println("1. System setup...")
	params, _ := privauth.Setup(30 * 24 * time.Hour)
	supervisorKeys, _ := privauth.GenerateSupervisorKeyPair(params)

	// Issue a batch of credentials (each credential uses an independent issuer key pair).
	n := 1000
	fmt.Printf("\n2. Issue %d credentials (each from a different issuer)...\n", n)

	userIDs := make([]*privauth.UserIdentity, n)
	attributesList := make([][]byte, n)
	credentials := make([]*privauth.Credential, n)

	for i := 0; i < n; i++ {
		userIDs[i], _ = privauth.GenerateUserIdentity()
		attributesList[i] = []byte(fmt.Sprintf("user_%d:confidential_data", i+1))

		// Independent issuer key pair per credential.
		issuerSK, issuerPK, _ := privauth.GenerateIssuerKeyPair(params)

		// Issue one credential via DisSign.
		cred, _, err := privauth.DisSign(
			params,
			issuerSK,
			issuerPK,
			supervisorKeys,
			userIDs[i],
			attributesList[i],
		)
		if err != nil {
			fmt.Printf("   ✗ Credential %d issuance failed: %v\n", i+1, err)
			return
		}
		credentials[i] = cred
	}
	fmt.Printf("   ✓ Issued %d credentials (each from a different issuer)\n", n)

	// Verifier challenge
	start := time.Now()
	fmt.Println("\n3. Verifier samples a random challenge...")
	challenge, _ := privauth.GenerateVerifierChallenge(n, params.Q)
	fmt.Printf("   ✓ Random vector Δ = (δ_1,...,δ_%d)\n", n)

	// Prover proof generation
	fmt.Println("\n4. Prover generates BatchVer1 proof...")
	proveStart := time.Now()
	proof, _ := privauth.BatchVer1Prove(params, credentials, challenge)
	fmt.Printf("   ✓ A = a^{k1·k2}\n")
	fmt.Printf("   ✓ B = b^{k1}\n")
	fmt.Printf("   ✓ σ = (Πσ_i^{δ_i})^{k1·k2}\n")
	fmt.Printf("   ✓ X' = (ΠX_i^{w_i·δ_i})^{k2}\n")
	fmt.Printf("   Proof generation time: %v\n", time.Since(proveStart))

	// Measure serialized sizes of key fields in the proof.
	fmt.Println("\n5. Measure proof field sizes (BatchVer1)...")

	// A (G1Affine) - use Bytes() for actual serialized size
	sizeA := len(proof.A.Bytes())
	fmt.Printf("   - proof.A (G1Affine): %d bytes\n", sizeA)

	// B (G1Affine)
	sizeB := len(proof.B.Bytes())
	fmt.Printf("   - proof.B (G1Affine): %d bytes\n", sizeB)

	// Sigma (G1Affine)
	sizeSigma := len(proof.Sigma.Bytes())
	fmt.Printf("   - proof.Sigma (G1Affine): %d bytes\n", sizeSigma)

	// XPrime (G2Affine)
	sizeXPrime := len(proof.XPrime.Bytes())
	fmt.Printf("   - proof.XPrime (G2Affine): %d bytes\n", sizeXPrime)

	// VerifyingKey - measure via JSON marshal
	sizeVK := 0
	if proof.VerifyingKey != nil {
		vkBytes, err := json.Marshal(proof.VerifyingKey)
		if err == nil {
			sizeVK = len(vkBytes)
		}
	}
	fmt.Printf("   - proof.VerifyingKey: %d bytes (%.2f KB)\n", sizeVK, float64(sizeVK)/1024)

	// PublicWitness - measure via JSON marshal
	sizePW := 0
	if proof.PublicWitness != nil {
		pwBytes, err := json.Marshal(proof.PublicWitness)
		if err == nil {
			sizePW = len(pwBytes)
		}
	}
	fmt.Printf("   - proof.PublicWitness: %d bytes (%.2f KB)\n", sizePW, float64(sizePW)/1024)

	totalProofSize := sizeA + sizeB + sizeSigma + sizeXPrime + sizePW
	fmt.Printf("\n   ✓ Total (selected fields): %d bytes (%.2f KB)\n",
		totalProofSize, float64(totalProofSize)/1024)

	// Verifier verification
	fmt.Println("\n6. Verifier verifies proof...")
	verifyStart := time.Now()
	valid := privauth.BatchVer1Verify(params, credentials, challenge, proof)
	fmt.Printf("   Verification time: %v\n", time.Since(verifyStart))

	if valid {
		fmt.Println("\n   ✓ BatchVer1 verification succeeded")
		fmt.Println("   → User attributes are hidden")
		fmt.Println("   → Verifier learns neither w_i nor attribute values")
		fmt.Printf("   → Check: e(σ,g) = e(A,ΠX_i^{δ_i}) · e(B,X')\n")
	} else {
		fmt.Println("\n   ✗ BatchVer1 verification failed")
	}
	fmt.Printf("\nTotal elapsed: %v\n", time.Since(start))
}

func demoBatchVer2() {
	start := time.Now()

	// System setup
	fmt.Println("1. System setup...")
	params, _ := privauth.Setup(30 * 24 * time.Hour)
	supervisorKeys, _ := privauth.GenerateSupervisorKeyPair(params)

	// Issue a batch of credentials (each credential uses an independent issuer key pair).
	n := 1000
	fmt.Printf("\n2. Issue %d credentials (each from a different issuer)...\n", n)

	userIDs := make([]*privauth.UserIdentity, n)
	attributesList := make([][]byte, n)
	credentials := make([]*privauth.Credential, n)

	for i := 0; i < n; i++ {
		userIDs[i], _ = privauth.GenerateUserIdentity()
		attributesList[i] = []byte(fmt.Sprintf("top_secret_attr_%d", i+1))

		// Independent issuer key pair per credential.
		issuerSK, issuerPK, _ := privauth.GenerateIssuerKeyPair(params)

		// Issue one credential via DisSign.
		cred, _, err := privauth.DisSign(
			params,
			issuerSK,
			issuerPK,
			supervisorKeys,
			userIDs[i],
			attributesList[i],
		)
		if err != nil {
			fmt.Printf("   ✗ Credential %d issuance failed: %v\n", i+1, err)
			return
		}
		credentials[i] = cred
	}
	fmt.Printf("   ✓ Issued %d credentials (each from a different issuer)\n", n)

	// Verifier challenge
	fmt.Println("\n3. Verifier samples a random challenge...")
	challenge, _ := privauth.GenerateVerifierChallenge(n, params.Q)
	fmt.Printf("   ✓ Random vector Δ = (δ_1,...,δ_%d)\n", n)

	// Prover proof generation
	fmt.Println("\n4. Prover generates BatchVer2 proof...")
	proveStart := time.Now()
	proof, _ := privauth.BatchVer2Prove(params, credentials, challenge)
	fmt.Printf("   ✓ A = a^{k1·k2}\n")
	fmt.Printf("   ✓ B = b^{k1}\n")
	fmt.Printf("   ✓ σ = (Πσ_i^{δ_i})^{k1·k2}\n")
	fmt.Printf("   ✓ X'' = ΠX_i^{δ_i}\n")
	fmt.Printf("   ✓ X' = (ΠX_i^{w_i·δ_i})^{k2}\n")
	fmt.Printf("   Proof generation time: %v\n", time.Since(proveStart))

	// Measure serialized sizes of key fields in the proof.
	fmt.Println("\n5. Measure proof field sizes (BatchVer2)...")

	// A (G1Affine)
	sizeA := len(proof.A.Bytes())
	fmt.Printf("   - proof.A (G1Affine): %d bytes\n", sizeA)

	// B (G1Affine)
	sizeB := len(proof.B.Bytes())
	fmt.Printf("   - proof.B (G1Affine): %d bytes\n", sizeB)

	// Sigma (G1Affine)
	sizeSigma := len(proof.Sigma.Bytes())
	fmt.Printf("   - proof.Sigma (G1Affine): %d bytes\n", sizeSigma)

	// XPrime (G2Affine)
	sizeXPrime := len(proof.XPrime.Bytes())
	fmt.Printf("   - proof.XPrime (G2Affine): %d bytes\n", sizeXPrime)

	// XPrime2 (G2Affine)
	sizeXPrime2 := len(proof.XPrime2.Bytes())
	fmt.Printf("   - proof.XPrime2 (G2Affine): %d bytes\n", sizeXPrime2)

	// VerifyingKey - measure via JSON marshal
	sizeVK := 0
	if proof.VerifyingKey != nil {
		vkBytes, err := json.Marshal(proof.VerifyingKey)
		if err == nil {
			sizeVK = len(vkBytes)
		}
	}
	fmt.Printf("   - proof.VerifyingKey: %d bytes (%.2f KB)\n", sizeVK, float64(sizeVK)/1024)

	// Groth16Proof - measure via JSON marshal
	sizeGroth16 := 0
	if proof.Groth16Proof != nil {
		g16Bytes, err := json.Marshal(proof.Groth16Proof)
		if err == nil {
			sizeGroth16 = len(g16Bytes)
		}
	}
	fmt.Printf("   - proof.Groth16Proof: %d bytes (%.2f KB)\n", sizeGroth16, float64(sizeGroth16)/1024)

	// PublicWitness - measure via JSON marshal
	sizePW := 0
	if proof.PublicWitness != nil {
		pwBytes, err := json.Marshal(proof.PublicWitness)
		if err == nil {
			sizePW = len(pwBytes)
		}
	}
	fmt.Printf("   - proof.PublicWitness: %d bytes (%.2f KB)\n", sizePW, float64(sizePW)/1024)

	totalProofSize := sizeA + sizeB + sizeSigma + sizeXPrime + sizeXPrime2 + sizeGroth16 + sizePW
	fmt.Printf("\n   ✓ Total (selected fields): %d bytes (%.2f KB)\n",
		totalProofSize, float64(totalProofSize)/1024)

	// Verifier verification (issuer identity not required)
	fmt.Println("\n6. Verifier verifies proof (issuer identity not required)...")
	verifyStart := time.Now()
	valid := privauth.BatchVer2Verify(params, proof)
	fmt.Printf("   Verification time: %v\n", time.Since(verifyStart))

	if valid {
		fmt.Println("\n   ✓ BatchVer2 verification succeeded")
		fmt.Println("   → User attributes are hidden")
		fmt.Println("   → Issuer identity is hidden")
		fmt.Println("   → Achieves fully anonymous authentication")
		fmt.Printf("   → Check: e(σ,g) = e(A,X'') · e(B,X')\n")
	} else {
		fmt.Println("\n   ✗ BatchVer2 verification failed")
		fmt.Println("   → Possible causes: pairing equation mismatch or Groth16 verification failure")
	}

	fmt.Printf("\nTotal elapsed: %v\n", time.Since(start))
}

func demoBatchVer3() {
	start := time.Now()

	// System setup
	fmt.Println("1. System setup...")
	params, _ := privauth.Setup(30 * 24 * time.Hour)
	supervisorKeys, _ := privauth.GenerateSupervisorKeyPair(params)

	// Issue a batch of credentials
	n := 100
	fmt.Printf("\n2. Issue %d credentials (each from a different issuer)...\n", n)

	userIDs := make([]*privauth.UserIdentity, n)
	attributesList := make([][]byte, n)
	credentials := make([]*privauth.Credential, n)

	for i := 0; i < n; i++ {
		userIDs[i], _ = privauth.GenerateUserIdentity()
		attributesList[i] = []byte(fmt.Sprintf("user_%d:confidential_data", i+1))

		issuerSK, issuerPK, _ := privauth.GenerateIssuerKeyPair(params)

		cred, _, err := privauth.DisSign(
			params,
			issuerSK,
			issuerPK,
			supervisorKeys,
			userIDs[i],
			attributesList[i],
		)
		if err != nil {
			fmt.Printf("   ✗ Credential %d issuance failed: %v\n", i+1, err)
			return
		}
		credentials[i] = cred
	}
	fmt.Printf("   ✓ Issued %d credentials (each from a different issuer)\n", n)

	// Verifier challenge
	fmt.Println("\n3. Verifier samples a random challenge...")
	challenge, _ := privauth.GenerateVerifierChallenge(n, params.Q)
	fmt.Printf("   ✓ Random vector Δ = (δ_1,...,δ_%d)\n", n)

	// Prover proof generation
	fmt.Println("\n4. Prover generates BatchVer3 proof (all verification in-circuit)...")
	proveStart := time.Now()
	proof, _ := privauth.BatchVer3Prove(params, credentials, challenge)
	fmt.Printf("   ✓ A = a^{k1·k2}\n")
	fmt.Printf("   ✓ B = b^{k1}\n")
	fmt.Printf("   ✓ σ = (Πσ_i^{δ_i})^{k1·k2}\n")
	fmt.Printf("   ✓ X' = (ΠX_i^{w_i·δ_i})^{k2}\n")
	fmt.Printf("   ✓ In-circuit checks: Σ(w_i·δ_i), Σ(X_i·δ_i), Σ(X_i·w_i·δ_i), w_i=H3(...)\n")
	fmt.Printf("   Proof generation time: %v\n", time.Since(proveStart))

	// Measure serialized sizes of key fields in the proof.
	fmt.Println("\n5. Measure proof field sizes (BatchVer3)...")

	// A (G1Affine)
	sizeA := len(proof.A.Bytes())
	fmt.Printf("   - proof.A (G1Affine): %d bytes\n", sizeA)

	// B (G1Affine)
	sizeB := len(proof.B.Bytes())
	fmt.Printf("   - proof.B (G1Affine): %d bytes\n", sizeB)

	// Sigma (G1Affine)
	sizeSigma := len(proof.Sigma.Bytes())
	fmt.Printf("   - proof.Sigma (G1Affine): %d bytes\n", sizeSigma)

	// XPrime (G2Affine)
	sizeXPrime := len(proof.XPrime.Bytes())
	fmt.Printf("   - proof.XPrime (G2Affine): %d bytes\n", sizeXPrime)

	// VerifyingKey
	sizeVK := 0
	if proof.VerifyingKey != nil {
		vkBytes, err := json.Marshal(proof.VerifyingKey)
		if err == nil {
			sizeVK = len(vkBytes)
		}
	}
	fmt.Printf("   - proof.VerifyingKey: %d bytes (%.2f KB)\n", sizeVK, float64(sizeVK)/1024)

	// Groth16Proof
	sizeGroth16 := 0
	if proof.Groth16Proof != nil {
		g16Bytes, err := json.Marshal(proof.Groth16Proof)
		if err == nil {
			sizeGroth16 = len(g16Bytes)
		}
	}
	fmt.Printf("   - proof.Groth16Proof: %d bytes (%.2f KB)\n", sizeGroth16, float64(sizeGroth16)/1024)

	// PublicWitness
	sizePW := 0
	if proof.PublicWitness != nil {
		pwBytes, err := json.Marshal(proof.PublicWitness)
		if err == nil {
			sizePW = len(pwBytes)
		}
	}
	fmt.Printf("   - proof.PublicWitness: %d bytes (%.2f KB)\n", sizePW, float64(sizePW)/1024)

	totalProofSize := sizeA + sizeB + sizeSigma + sizeXPrime + sizeGroth16 + sizePW
	fmt.Printf("\n   ✓ Total (selected fields): %d bytes (%.2f KB)\n",
		totalProofSize, float64(totalProofSize)/1024)

	// Verifier verification (Groth16 only)
	fmt.Println("\n6. Verifier verifies proof (Groth16 only, no pairings)...")
	verifyStart := time.Now()
	valid := privauth.BatchVer3Verify(params, proof)
	fmt.Printf("   Verification time: %v\n", time.Since(verifyStart))

	if valid {
		fmt.Println("\n   ✓ BatchVer3 verification succeeded")
		fmt.Println("   → User attributes are hidden")
		fmt.Println("   → Issuer identity is hidden")
		fmt.Println("   → All verification logic is inside the circuit")
		fmt.Println("   → Verifier checks Groth16 only")
		fmt.Println("   → Fastest verification (no pairings, no loops)")
	} else {
		fmt.Println("\n   ✗ BatchVer3 verification failed")
	}

	fmt.Printf("\nTotal elapsed: %v\n", time.Since(start))
}

func demoBatchVer4() {
	start := time.Now()

	// System setup
	fmt.Println("1. System setup...")
	params, _ := privauth.Setup(30 * 24 * time.Hour)
	supervisorKeys, _ := privauth.GenerateSupervisorKeyPair(params)

	// Issue a batch of credentials
	n := 1000
	fmt.Printf("\n2. Issue %d credentials (each from a different issuer)...\n", n)

	userIDs := make([]*privauth.UserIdentity, n)
	attributesList := make([][]byte, n)
	credentials := make([]*privauth.Credential, n)

	for i := 0; i < n; i++ {
		userIDs[i], _ = privauth.GenerateUserIdentity()
		attributesList[i] = []byte(fmt.Sprintf("user_%d:top_secret", i+1))

		issuerSK, issuerPK, _ := privauth.GenerateIssuerKeyPair(params)

		cred, _, err := privauth.DisSign(
			params,
			issuerSK,
			issuerPK,
			supervisorKeys,
			userIDs[i],
			attributesList[i],
		)
		if err != nil {
			fmt.Printf("   ✗ Credential %d issuance failed: %v\n", i+1, err)
			return
		}
		credentials[i] = cred
	}
	fmt.Printf("   ✓ Issued %d credentials (each from a different issuer)\n", n)

	// Verifier challenge
	fmt.Println("\n3. Verifier samples a random challenge...")
	challenge, _ := privauth.GenerateVerifierChallenge(n, params.Q)
	fmt.Printf("   ✓ Random vector Δ = (δ_1,...,δ_%d)\n", n)

	// Prover proof generation
	fmt.Println("\n4. Prover generates BatchVer4 proof (fully-ZK BatchVer2)...")
	proveStart := time.Now()
	proof, _ := privauth.BatchVer4Prove(params, credentials, challenge)
	fmt.Printf("   ✓ A = a^{k1·k2}\n")
	fmt.Printf("   ✓ B = b^{k1}\n")
	fmt.Printf("   ✓ σ = (Πσ_i^{δ_i})^{k1·k2}\n")
	fmt.Printf("   ✓ X'' = ΠX_i^{δ_i}\n")
	fmt.Printf("   ✓ X' = (ΠX_i^{w_i·δ_i})^{k2}\n")
	fmt.Printf("   ✓ In-circuit checks: Σ(w_i·δ_i), Σ(X_i·δ_i), Σ(X_i·w_i·δ_i), w_i=H3(...), k1/k2 non-zero\n")
	fmt.Printf("   Proof generation time: %v\n", time.Since(proveStart))

	// Measure serialized sizes of key fields in the proof.
	fmt.Println("\n5. Measure proof field sizes (BatchVer4)...")

	// A (G1Affine)
	sizeA := len(proof.A.Bytes())
	fmt.Printf("   - proof.A (G1Affine): %d bytes\n", sizeA)

	// B (G1Affine)
	sizeB := len(proof.B.Bytes())
	fmt.Printf("   - proof.B (G1Affine): %d bytes\n", sizeB)

	// Sigma (G1Affine)
	sizeSigma := len(proof.Sigma.Bytes())
	fmt.Printf("   - proof.Sigma (G1Affine): %d bytes\n", sizeSigma)

	// XPrime (G2Affine)
	sizeXPrime := len(proof.XPrime.Bytes())
	fmt.Printf("   - proof.XPrime (G2Affine): %d bytes\n", sizeXPrime)

	// XPrime2 (G2Affine)
	sizeXPrime2 := len(proof.XPrime2.Bytes())
	fmt.Printf("   - proof.XPrime2 (G2Affine): %d bytes\n", sizeXPrime2)

	// VerifyingKey
	sizeVK := 0
	if proof.VerifyingKey != nil {
		vkBytes, err := json.Marshal(proof.VerifyingKey)
		if err == nil {
			sizeVK = len(vkBytes)
		}
	}
	fmt.Printf("   - proof.VerifyingKey: %d bytes (%.2f KB)\n", sizeVK, float64(sizeVK)/1024)

	// Groth16Proof
	sizeGroth16 := 0
	if proof.Groth16Proof != nil {
		g16Bytes, err := json.Marshal(proof.Groth16Proof)
		if err == nil {
			sizeGroth16 = len(g16Bytes)
		}
	}
	fmt.Printf("   - proof.Groth16Proof: %d bytes (%.2f KB)\n", sizeGroth16, float64(sizeGroth16)/1024)

	// PublicWitness
	sizePW := 0
	if proof.PublicWitness != nil {
		pwBytes, err := json.Marshal(proof.PublicWitness)
		if err == nil {
			sizePW = len(pwBytes)
		}
	}
	fmt.Printf("   - proof.PublicWitness: %d bytes (%.2f KB)\n", sizePW, float64(sizePW)/1024)

	totalProofSize := sizeA + sizeB + sizeSigma + sizeXPrime + sizeXPrime2 + sizeGroth16 + sizePW
	fmt.Printf("\n   ✓ Total (selected fields): %d bytes (%.2f KB)\n",
		totalProofSize, float64(totalProofSize)/1024)

	// Verifier verification (Groth16 only)
	fmt.Println("\n6. Verifier verifies proof (Groth16 only, no pairings)...")
	verifyStart := time.Now()
	valid := privauth.BatchVer4Verify(params, proof)
	fmt.Printf("   Verification time: %v\n", time.Since(verifyStart))

	if valid {
		fmt.Println("\n   ✓ BatchVer4 verification succeeded")
		fmt.Println("   → User attributes are hidden")
		fmt.Println("   → Issuer identity is hidden")
		fmt.Println("   → All verification logic is inside the circuit (including w_i and k1/k2 checks)")
		fmt.Println("   → Verifier checks Groth16 only")
		fmt.Println("   → Fastest verification (no pairings, no loops)")
	} else {
		fmt.Println("\n   ✗ BatchVer4 verification failed")
	}

	fmt.Printf("\nTotal elapsed: %v\n", time.Since(start))
}

func repeatStr(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
