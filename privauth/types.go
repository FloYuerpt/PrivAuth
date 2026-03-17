package privauth

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimcfr "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// SystemParameters are public parameters θ=(q, g, G1, G2, GT, e, φ, H1, H2, H3).
type SystemParameters struct {
	Q   *big.Int       // Group order.
	G   bn254.G1Affine // G1 generator.
	Phi *big.Int       // Validity bound φ (unix timestamp).
}

// IssuerSecretKey is the issuer secret key.
type IssuerSecretKey struct {
	Xi *big.Int // x_i
}

// IssuerPublicKey is the issuer public key.
type IssuerPublicKey struct {
	Xi bn254.G2Affine // X_i = g2^{x_i}
}

// SupervisorKeys is the supervisor key pair.
type SupervisorKeys struct {
	PrivateKey *big.Int       // Secret key.
	PublicKey  bn254.G1Affine // Public key pk_S.
}

// UserIdentity is a user's identity.
type UserIdentity struct {
	ID []byte // ID_U
}

// Credential is a user credential.
type Credential struct {
	// Basic fields.
	Identity   []byte   // ID_i
	Attributes []byte   // m_i
	ValidUntil *big.Int // φ (unix timestamp)

	// Signature.
	Sigma bn254.G1Affine // σ_i = a^{x_i}·b^{x_i·w_i}

	// Weight.
	Wi *big.Int // w_i = H3(ID_i || m_i || φ)

	// Issuer.
	IssuerPK bn254.G2Affine // X_i (in G2)
}

// EscrowCiphertext is the identity escrow ciphertext.
type EscrowCiphertext struct {
	C1 bn254.G1Affine // r·G
	C2 bn254.G1Affine // r·pk_S + ID_U
}

// BatchVerifyProof is the BatchVer1 proof.
type BatchVerifyProof struct {
	// BatchVer1 values.
	A      bn254.G1Affine // A = a^{k1·k2} in G1
	B      bn254.G1Affine // B = b^{k1}    in G1
	Sigma  bn254.G1Affine // σ = (Πσ_i^{δ_i})^{k1·k2}
	XPrime bn254.G2Affine // X' = (ΠX_i^{w_i·δ_i})^{k2} in G2

	// Randomness (kept nil in the exported proof for ZK).
	K1 *big.Int
	K2 *big.Int

	// ZK proof (Groth16).
	Groth16Proof  groth16.Proof        // Groth16 proof
	VerifyingKey  groth16.VerifyingKey // Verification key
	PublicWitness witness.Witness      // Public witness
	ZKProof       []byte               // Reserved for compatibility (optional)
}

// BatchVerifyProof2 is the BatchVer2 proof (issuer-hidden).
type BatchVerifyProof2 struct {
	// BatchVer2 values.
	A       bn254.G1Affine // A = a^{k1·k2} in G1
	B       bn254.G1Affine // B = b^{k1}    in G1
	Sigma   bn254.G1Affine // σ = (Πσ_i^{δ_i})^{k1·k2}
	XPrime  bn254.G2Affine // X' = (ΠX_i^{w_i·δ_i})^{k2} in G2
	XPrime2 bn254.G2Affine // X'' = (ΠX_i^{δ_i})^{k2} in G2

	// Randomness.
	K1 *big.Int
	K2 *big.Int

	// ZK proof (Groth16).
	Groth16Proof  groth16.Proof        // Groth16 proof
	VerifyingKey  groth16.VerifyingKey // Verification key
	PublicWitness witness.Witness      // Public witness
	ZKProof       []byte               // Reserved for compatibility (optional)
}

// VerifierChallenge is the verifier challenge.
type VerifierChallenge struct {
	Delta []*big.Int // Δ=(δ_1,...,δ_n)
}

// Hash1 implements H1: {0,1}* → G1, used to derive a = H1(φ).
func Hash1(phi *big.Int) bn254.G1Affine {
	var point bn254.G1Affine
	phiBytes := phi.Bytes()
	point, _ = bn254.HashToG1(phiBytes, []byte("PrivAuth_H1"))
	return point
}

// Hash2 implements H2: {0,1}* → G1, used to derive b = H2(φ).
func Hash2(phi *big.Int) bn254.G1Affine {
	var point bn254.G1Affine
	phiBytes := phi.Bytes()
	point, _ = bn254.HashToG1(phiBytes, []byte("PrivAuth_H2"))
	return point
}

// Hash1G2 hashes φ into G2 (used in batch verification variants).
func Hash1G2(phi *big.Int) bn254.G2Affine {
	var point bn254.G2Affine
	phiBytes := phi.Bytes()
	point, _ = bn254.HashToG2(phiBytes, []byte("PrivAuth_H1_G2"))
	return point
}

// Hash2G2 hashes φ into G2 (used in batch verification variants).
func Hash2G2(phi *big.Int) bn254.G2Affine {
	var point bn254.G2Affine
	phiBytes := phi.Bytes()
	point, _ = bn254.HashToG2(phiBytes, []byte("PrivAuth_H2_G2"))
	return point
}

// Hash3 implements H3: {0,1}* → Zq, used to derive w_i = H3(ID_i || m_i || φ).
func Hash3(identity, attributes []byte, phi *big.Int) *big.Int {
	// Field-element approach: map (ID, m, φ) into BN254 field elements, then
	// feed their canonical bytes into MiMC.
	var idFe, mFe, phiFe fr.Element
	idFe.SetBytes(identity)
	mFe.SetBytes(attributes)
	phiFe.SetBigInt(phi)

	idBytes := idFe.Bytes()
	mBytes := mFe.Bytes()
	phiBytes := phiFe.Bytes()

	h := mimcfr.NewMiMC()
	h.Reset()
	_, _ = h.Write(idBytes[:])
	_, _ = h.Write(mBytes[:])
	_, _ = h.Write(phiBytes[:])
	digest := h.Sum(nil)

	var outFe fr.Element
	outFe.SetBytes(digest)
	out := new(big.Int)
	outFe.BigInt(out)
	return out
}
