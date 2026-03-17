package privauth

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Setup initializes the system and returns public parameters.
func Setup(validityPeriod time.Duration) (*SystemParameters, error) {
	// Group order q.
	q := fr.Modulus()

	// G1 generator.
	_, _, g1Gen, _ := bn254.Generators()

	// Validity bound φ as a unix timestamp.
	phi := big.NewInt(time.Now().Add(validityPeriod).Unix())

	params := &SystemParameters{
		Q:   new(big.Int).Set(q),
		G:   g1Gen,
		Phi: phi,
	}

	return params, nil
}

// GenerateIssuerKeyPair generates an issuer key pair.
func GenerateIssuerKeyPair(params *SystemParameters) (*IssuerSecretKey, *IssuerPublicKey, error) {
	// Sample secret key x_i ∈ Zq.
	xi, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, nil, err
	}

	// Compute public key X_i = g2^{x_i}.
	_, g2GenJac, _, _ := bn254.Generators()
	var Xi bn254.G2Jac
	Xi.ScalarMultiplication(&g2GenJac, xi)

	var XiAffine bn254.G2Affine
	XiAffine.FromJacobian(&Xi)

	sk := &IssuerSecretKey{Xi: xi}
	pk := &IssuerPublicKey{Xi: XiAffine}

	return sk, pk, nil
}

// GenerateSupervisorKeyPair generates the supervisor key pair.
func GenerateSupervisorKeyPair(params *SystemParameters) (*SupervisorKeys, error) {
	// Sample secret key.
	sk, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	// Compute public key pk_S = g^{sk}.
	var gJac2 bn254.G1Jac
	gJac2.FromAffine(&params.G)
	var pkJac bn254.G1Jac
	pkJac.ScalarMultiplication(&gJac2, sk)

	var pkAffine bn254.G1Affine
	pkAffine.FromJacobian(&pkJac)

	return &SupervisorKeys{
		PrivateKey: sk,
		PublicKey:  pkAffine,
	}, nil
}

// GenerateUserIdentity generates a fresh user identity.
func GenerateUserIdentity() (*UserIdentity, error) {
	// 32-byte random identifier.
	id := make([]byte, 32)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	return &UserIdentity{ID: id}, nil
}
