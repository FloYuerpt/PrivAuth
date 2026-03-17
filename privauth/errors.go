package privauth

import "errors"

var (
	// ErrInvalidProof indicates a proof is invalid.
	ErrInvalidProof = errors.New("invalid proof")

	// ErrInvalidCredential indicates a credential is invalid.
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrInvalidBatchSize indicates the batch size is invalid.
	ErrInvalidBatchSize = errors.New("invalid batch size")

	// ErrNullifierUsed indicates a nullifier has already been used.
	ErrNullifierUsed = errors.New("nullifier already used")

	// ErrInvalidSignature indicates a signature is invalid.
	ErrInvalidSignature = errors.New("invalid signature")
)
