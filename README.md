# PrivAuth - A Lightweight Multi-Attribute Batch Authentication Protocol with Anonymity and Traceability 

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

#### BatchVer3 - Fully-ZK BatchVer1 (In-Circuit Verification)

**Steps**:

1. Same computation as BatchVer1, but **all verification logic is moved into the Groth16 circuit**
2. Verifier **only checks the Groth16 proof** (no pairing computation required)
3. Minimal verification cost for the verifier

```go
proof, _ := BatchVer3Prove(params, credentials, challenge)
valid := BatchVer3Verify(params, proof)
```

#### BatchVer4 - Fully-ZK BatchVer2 (Fastest Verify + Issuer-Hiding)

**Steps**:

1. Same as BatchVer2, but **all verification logic is in-circuit**
2. Verifier only checks the Groth16 proof
3. Combines issuer-hiding with the fastest verification

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
├── batchver.go           # BatchVer1/2/3/4 prove/verify variants
├── zk_circuit.go         # Groth16 circuits (BatchVer1–4)
├── errors.go             # Error definitions
├── demo/                 # Demo application
│   ├── main.go           # DisSign, BatchVer1–4 demos
│   └── go.mod
└── revocation/           # Credential revocation (zk-SNARK)
    ├── cmd/revocation/   # Main executable
    ├── internal/curvebench/  # Emulated curve/field benchmarks
    └── README.md
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

challenge, _ := privauth.GenerateVerifierChallenge(n, params.Q)

// BatchVer1: attribute-hiding (pairing-based verify)
proof1, _ := privauth.BatchVer1Prove(params, credentials, challenge)
valid1 := privauth.BatchVer1Verify(params, credentials, challenge, proof1)

// BatchVer2: attribute-hiding + issuer-hiding (pairing-based verify)
proof2, _ := privauth.BatchVer2Prove(params, credentials, challenge)
valid2 := privauth.BatchVer2Verify(params, proof2)

// BatchVer3: fully-ZK BatchVer1 (Groth16-only verify)
proof3, _ := privauth.BatchVer3Prove(params, credentials, challenge)
valid3 := privauth.BatchVer3Verify(params, proof3)

// BatchVer4: fully-ZK BatchVer2 (fastest verify + issuer-hiding)
proof4, _ := privauth.BatchVer4Prove(params, credentials, challenge)
valid4 := privauth.BatchVer4Verify(params, proof4)
```

## Running Demo

```bash
cd privauth/demo
go run main.go
```

The demo runs five scenarios: DisSign, BatchVer1, BatchVer2, BatchVer3, and BatchVer4.

## Running Tests

```bash
cd privauth

# Run all tests
go test -v ./...

# Revocation module benchmarks (emulated curve/field)
cd revocation
go test -v ./internal/curvebench/...
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
- BatchVer1/2: proves correctness of \(X'\) and \(X''\); verifier uses pairing
- BatchVer3/4: full in-circuit verification; verifier only checks Groth16 proof
- Does not reveal private values such as \(k2\) and \(w_i\)

## Difference from the Simplified Version

The original version (e.g. `circuit.go`, `issue.go`, `verify.go`) is a simplified hash-based scheme.

The new implementation (`types.go`, `dissign.go`, `batchver.go`) follows the paper and uses the full pairing-based construction:

| Property | Simplified | Full (new) |
|------|---------|--------------|
| Foundation | hashes | bilinear pairings |
| Signature | `Hash(sk,pk,comm)` | \(a^{x_i}\cdot b^{x_i\cdot w_i}\) |
| Verification | hash compare | pairing / Groth16 |
| Batch verification | not supported | BatchVer1/2/3/4 |
| Anonymity | basic | full |
| Complexity | \(O(n)\) | \(O(1)\) |

## Dependencies

```go
require (
    github.com/consensys/gnark v0.11.0
    github.com/consensys/gnark-crypto v0.14.0
)
```

- Go 1.24+

## Revocation Module

The `revocation/` subdirectory provides a credential revocation verification system based on zk-SNARK (gnark + BN254):

- **Accumulator-based revocation**: supports m accumulators, k IDs per accumulator, n issuers
- **Circuit**: accumulator verification + aggregate verification
- See `revocation/README.md` for build/run and benchmark details
