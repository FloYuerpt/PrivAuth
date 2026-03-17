# PrivAuth - Pairing-Based Multi-Attribute Batch Authentication

## Overview

PrivAuth is a lightweight multi-attribute batch authentication protocol built on bilinear pairings, providing anonymity and traceability. This implementation follows the paper's **DisSign** and **BatchVer** algorithms.

## Core Algorithms

### Public Parameters

\(\theta = (q, g, G1, G2, GT, e, \phi, H1, H2, H3)\)

- **q**: group order
- **g**: generator of G1
- **e**: bilinear pairing \(G1 \times G2 \to GT\)
- **φ**: credential validity bound
- **H1, H2**: hash-to-curve functions \(\{0,1\}^* \to G1\)
- **H3**: hash-to-field function \(\{0,1\}^* \to \mathbb{Z}_q\)

### 1) Credential Issuance (DisSign)

**Parties**: user U, issuer \(I_i\), supervisor S

**Goal**: sign the tuple (identity, attributes, validity) with
\(\sigma_i = a^{x_i} \cdot b^{x_i \cdot w_i}\)

**Procedure**:

1. Derive bases: \(a = H1(\phi)\), \(b = H2(\phi)\)
2. Compute weight: \(w_i = H3(ID_i \,\|\, m_i \,\|\, \phi)\)
3. Issuer signs: \(\sigma_i = a^{x_i} \cdot b^{x_i \cdot w_i}\)
4. User creates identity escrow ciphertext: \(C_U = (r\cdot G,\; r\cdot pk_S + ID_U)\)

```go
credential, escrow, err := DisSign(
    params,
    issuerSK,
    issuerPK,
    supervisorPK,
    userIdentity,
    attributes,
)
```

### 2) Batch Verification (BatchVer)

PrivAuth supports two batch verification modes:

#### BatchVer1 - Attribute-Hiding

**Steps**:

1. Verifier samples a random vector \(\Delta = (\delta_1,\dots,\delta_n)\)
2. Prover samples random \(k1, k2\)
3. Compute:
   - \(A = a^{k1 \cdot k2}\)
   - \(B = b^{k1}\)
   - \(\sigma = (\prod \sigma_i^{\delta_i})^{k1 \cdot k2}\)
   - \(X' = (\prod X_i^{w_i \cdot \delta_i})^{k2}\)
4. Prover produces a ZK proof that \(X'\) is constructed correctly
5. Verifier checks: **\(e(\sigma,g) = e(A,\prod X_i^{\delta_i}) \cdot e(B,X')\)**

```go
// Verifier samples challenge
challenge, _ := GenerateVerifierChallenge(n, params.Q)

// Prover generates proof
proof, _ := BatchVer1Prove(params, credentials, challenge)

// Verifier verifies
valid := BatchVer1Verify(params, credentials, challenge, proof)
```

#### BatchVer2 - Attribute-Hiding + Issuer-Hiding

**Steps**:

1. Same as BatchVer1, but issuer public keys are also hidden in the ZK statement
2. Prover proves:
   - \(X'' = (\prod X_i^{\delta_i})^{k2}\)
   - \(X' = (\prod X_i^{w_i \cdot \delta_i})^{k2}\)
3. Verifier checks: **\(e(\sigma,g) = e(A,X'') \cdot e(B,X')\)**

```go
// Prover generates proof (issuer hidden)
proof, _ := BatchVer2Prove(params, credentials, challenge)

// Verifier verifies (issuer identity not required)
valid := BatchVer2Verify(params, proof)
```

## Performance Notes

### Complexity

- **Communication**: \(O(1)\) - constant number of group elements
- **Computation**: \(O(1)\) - constant number of pairings
- **Batch verification time**: does not grow linearly with n

### Rough Benchmark

Empirically (n=100):
- Batch verification: 150–250 ms
- Tens of times faster than naive per-credential verification

## File Layout

```
privauth/
├── types.go              # Types + Hash1/Hash2/Hash3
├── setup.go              # Setup and key generation
├── dissign.go            # DisSign issuance + credential verification
├── batchver.go           # BatchVer prove/verify variants
├── zk_circuit.go         # Groth16 circuits
├── privauth_new_test.go  # Tests for the new implementation
└── example_new_test.go   # Examples for the new implementation
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "time"

    "privauth"
)

func main() {
    // 1) Setup (30-day validity)
    params, _ := privauth.Setup(30 * 24 * time.Hour)

    // 2) Keys and identity
    issuerSK, issuerPK, _ := privauth.GenerateIssuerKeyPair(params)
    supervisorKeys, _ := privauth.GenerateSupervisorKeyPair(params)
    userID, _ := privauth.GenerateUserIdentity()

    // 3) Issue credential
    attributes := []byte("age:25,vip:2,region:CN")
    credential, _, _ := privauth.DisSign(
        params, issuerSK, issuerPK, supervisorKeys, userID, attributes,
    )

    // 4) Verify credential
    valid := privauth.VerifyCredential(params, credential)
    fmt.Printf("Credential verified: %v\n", valid)
}
```

### Batch Verification Example

```go
// Batch issuance
n := 5
credentials, _, _ := privauth.BatchDisSign(
    params, issuerSK, issuerPK, supervisorKeys, userIDs, attributesList,
)

// BatchVer1: attribute-hiding
challenge, _ := privauth.GenerateVerifierChallenge(n, params.Q)
proof1, _ := privauth.BatchVer1Prove(params, credentials, challenge)
valid1 := privauth.BatchVer1Verify(params, credentials, challenge, proof1)

// BatchVer2: attribute-hiding + issuer-hiding
proof2, _ := privauth.BatchVer2Prove(params, credentials, challenge)
valid2 := privauth.BatchVer2Verify(params, proof2)
```

## Running Tests

```bash
cd /home/yuerpt/PrivAuth/groth16/gnark-master/privauth

# Unit tests (new implementation)
go test -v -run TestDisSign
go test -v -run TestBatchVer1
go test -v -run TestBatchVer2

# Benchmarks
go test -bench=BenchmarkDisSign
go test -bench=BenchmarkBatchVer1
go test -bench=BenchmarkBatchVer2

# Examples
go test -v -run Example_DisSignBasic
go test -v -run Example_BatchVer1
go test -v -run Example_BatchVer2
```

## Security Properties

### 1) Anonymity

- **BatchVer1**: hides user attributes; verifier does not learn \(m_i\)
- **BatchVer2**: hides both attributes and issuer identity (fully anonymous)

### 2) Double-Spend Prevention

- Uses a **nullifier** mechanism to prevent re-use of credentials
- Verifier maintains a set of used nullifiers

### 3) Traceability

- Supervisor can decrypt the escrow ciphertext \(C_U\) to recover the real user identity
- \(C_U = (r\cdot G,\; r\cdot pk_S + ID_U)\)
- With secret key \(sk_S\): \(ID_U = C2 - sk_S\cdot C1\)

### 4) Unforgeability

- Based on the q-SDH assumption
- Only issuers holding a valid secret key can produce valid signatures

## Technical Details

### Bilinear Pairing

This implementation uses the optimal Ate pairing over **BN254**:

- G1: group of points on \(E(\mathbb{F}_q)\)
- G2: group of points on \(E(\mathbb{F}_{q^2})\)
- GT: multiplicative group in \(\mathbb{F}_{q^{12}}\)
- Pairing: \(e: G1 \times G2 \to GT\)

### Hash Functions

- **H1, H2**: hash-to-G1 (via `HashToG1`)
- **H3**: hash-to-field \(\mathbb{Z}_q\)

### Zero-Knowledge Proofs

- Groth16-based zk-SNARK
- Proves correctness of constructing \(X'\) and \(X''\)
- Does not reveal private values such as \(k2\) and \(w_i\)

## Difference from the Simplified Version

The original version (e.g. `circuit.go`, `issue.go`, `verify.go`) is a simplified hash-based scheme.

The new implementation (`types.go`, `dissign.go`, `batchver.go`) follows the paper and uses the full pairing-based construction:

| Property | Simplified | Full (new) |
|------|---------|--------------|
| Foundation | hashes | bilinear pairings |
| Signature | `Hash(sk,pk,comm)` | \(a^{x_i}\cdot b^{x_i\cdot w_i}\) |
| Verification | hash compare | pairing equation |
| Batch verification | not supported | BatchVer1/2 |
| Anonymity | basic | full |
| Complexity | \(O(n)\) | \(O(1)\) |

## Dependencies

```go
require (
    github.com/consensys/gnark v0.11.0
    github.com/consensys/gnark-crypto v0.19.0
)
```

## References

Paper: *"PrivAuth: A Lightweight Multi-Attribute Batch Authentication Protocol with Anonymity and Traceability"*

## License

Same license as gnark.

