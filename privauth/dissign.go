package privauth

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// DisSign issues a credential signature.
// Parties: user U, issuer I_i, supervisor S.
// Input: user identity ID_i, attributes m_i, issuer secret key x_i, validity bound φ.
// Output: signature σ_i and identity escrow ciphertext C_U.
func DisSign(
	params *SystemParameters,
	issuerSK *IssuerSecretKey,
	issuerPK *IssuerPublicKey,
	supervisorPK *SupervisorKeys,
	userIdentity *UserIdentity,
	attributes []byte,
) (*Credential, *EscrowCiphertext, error) {

	// 1. a = H1(φ), b = H2(φ)
	a := Hash1(params.Phi)
	b := Hash2(params.Phi)

	// 2. w_i = H3(ID_i || m_i || φ)
	wi := Hash3(userIdentity.ID, attributes, params.Phi)

	// 3. σ_i = a^{x_i} · b^{x_i·w_i}

	// a^{x_i}
	var aJac bn254.G1Jac
	aJac.FromAffine(&a)
	var aXi bn254.G1Jac
	aXi.ScalarMultiplication(&aJac, issuerSK.Xi)

	// Compute x_i · w_i.
	xiWi := new(big.Int).Mul(issuerSK.Xi, wi)
	xiWi.Mod(xiWi, params.Q)

	// Compute b^{x_i·w_i}.
	var bJac bn254.G1Jac
	bJac.FromAffine(&b)
	var bXiWi bn254.G1Jac
	bXiWi.ScalarMultiplication(&bJac, xiWi)

	// σ_i = a^{x_i} · b^{x_i·w_i}
	var sigmaJac bn254.G1Jac
	sigmaJac.Set(&aXi)
	sigmaJac.AddAssign(&bXiWi)

	var sigma bn254.G1Affine
	sigma.FromJacobian(&sigmaJac)

	// 4. Identity escrow ciphertext C_U = (r·G, r·pk_S + ID_U).
	escrow, err := generateEscrowCiphertext(params, supervisorPK, userIdentity.ID)
	if err != nil {
		return nil, nil, err
	}

	// Assemble credential.
	credential := &Credential{
		Identity:   userIdentity.ID,
		Attributes: attributes,
		ValidUntil: params.Phi,
		Sigma:      sigma,
		Wi:         wi,
		IssuerPK:   issuerPK.Xi,
	}

	return credential, escrow, nil
}

// BatchDisSign issues a batch of credentials.
func BatchDisSign(
	params *SystemParameters,
	issuerSK *IssuerSecretKey,
	issuerPK *IssuerPublicKey,
	supervisorPK *SupervisorKeys,
	userIdentities []*UserIdentity,
	attributesList [][]byte,
) ([]*Credential, []*EscrowCiphertext, error) {

	if len(userIdentities) != len(attributesList) {
		return nil, nil, ErrInvalidBatchSize
	}

	n := len(userIdentities)
	credentials := make([]*Credential, n)
	escrows := make([]*EscrowCiphertext, n)

	for i := 0; i < n; i++ {
		cred, escrow, err := DisSign(
			params,
			issuerSK,
			issuerPK,
			supervisorPK,
			userIdentities[i],
			attributesList[i],
		)
		if err != nil {
			return nil, nil, err
		}
		credentials[i] = cred
		escrows[i] = escrow
	}

	return credentials, escrows, nil
}

// generateEscrowCiphertext creates the identity escrow ciphertext.
// C_U = (r·G, r·pk_S + ID_U)
func generateEscrowCiphertext(
	params *SystemParameters,
	supervisorPK *SupervisorKeys,
	userID []byte,
) (*EscrowCiphertext, error) {

	// Sample r ∈ Zq.
	r, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	// C1 = r·G
	var gJac bn254.G1Jac
	gJac.FromAffine(&params.G)
	var c1Jac bn254.G1Jac
	c1Jac.ScalarMultiplication(&gJac, r)
	var c1 bn254.G1Affine
	c1.FromJacobian(&c1Jac)

	// Map ID_U to a G1 point.
	idPoint, err := bn254.HashToG1(userID, []byte("PrivAuth_ID"))
	if err != nil {
		return nil, err
	}

	// r·pk_S
	var pkSJac bn254.G1Jac
	pkSJac.FromAffine(&supervisorPK.PublicKey)
	var rPkS bn254.G1Jac
	rPkS.ScalarMultiplication(&pkSJac, r)

	// C2 = r·pk_S + ID_U
	var c2Jac bn254.G1Jac
	c2Jac.Set(&rPkS)
	c2Jac.AddMixed(&idPoint)

	var c2 bn254.G1Affine
	c2.FromJacobian(&c2Jac)

	return &EscrowCiphertext{
		C1: c1,
		C2: c2,
	}, nil
}

// VerifyCredential verifies a single credential.
// Pairing check: e(σ_i, g) = e(a, X_i) · e(b, X_i^{w_i}).
func VerifyCredential(
	params *SystemParameters,
	credential *Credential,
) bool {
	// Compute a = H1(φ), b = H2(φ) in G1.
	a := Hash1(credential.ValidUntil)
	b := Hash2(credential.ValidUntil)

	// Get the G2 generator (for e(σ, g2)).
	_, g2GenJac, _, _ := bn254.Generators()
	var g2Gen bn254.G2Affine
	g2Gen.FromJacobian(&g2GenJac)

	// Compute X_i^{w_i} ∈ G2.
	var issuerPKJac bn254.G2Jac
	issuerPKJac.FromAffine(&credential.IssuerPK)
	var xiWi bn254.G2Jac
	xiWi.ScalarMultiplication(&issuerPKJac, credential.Wi)
	var xiWiAffine bn254.G2Affine
	xiWiAffine.FromJacobian(&xiWi)

	// Left: e(σ_i, g2).
	left, err := bn254.Pair([]bn254.G1Affine{credential.Sigma}, []bn254.G2Affine{g2Gen})
	if err != nil {
		return false
	}

	// Right: e(a, X_i) · e(b, X_i^{w_i}).
	pairing1, err := bn254.Pair([]bn254.G1Affine{a}, []bn254.G2Affine{credential.IssuerPK})
	if err != nil {
		return false
	}
	pairing2, err := bn254.Pair([]bn254.G1Affine{b}, []bn254.G2Affine{xiWiAffine})
	if err != nil {
		return false
	}
	var right bn254.GT
	right.Mul(&pairing1, &pairing2)

	return left.Equal(&right)
}
