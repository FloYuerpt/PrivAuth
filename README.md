# PrivAuth

A **lightweight multi-attribute batch authentication protocol** with anonymity and traceability, based on bilinear pairings.

## Paper

- [PrivAuth: A Lightweight Multi-Attribute Batch Authentication Protocol with Anonymity and Traceability]

## Go Implementation

This repository contains a **Go reference implementation** of the protocol (DisSign, BatchVer1/2/3/4) using [gnark](https://github.com/consensys/gnark) and BN254.

| Location   | Description |
|-----------|-------------|
| **`privauth/`** | Core library: setup, credential issuance (DisSign), batch verification (BatchVer1–4), ZK circuits |
| **`privauth/demo/`** | Demo binary that runs all algorithms and prints timings |

### Quick Start

```bash
# Clone the repo
git clone https://github.com/FloYuerpt/PrivAuth.git
cd PrivAuth

# Run the demo (requires Go 1.24+)
cd privauth/demo
go run .
```

### Build & Test

```bash
cd privauth
go build ./...
go test ./...

cd demo
go build -o privauth-demo .
./privauth-demo
```

### Dependencies

- [github.com/consensys/gnark](https://github.com/consensys/gnark) (zk-SNARK backend)
- [github.com/consensys/gnark-crypto](https://github.com/consensys/gnark-crypto) (BN254, pairings)

See **`privauth/README.md`** for full API documentation, algorithm descriptions, and security properties.

## Repository Layout

```
PrivAuth/
├── README.md                 # This file
├── A_Lightweight_...*.pdf    # Protocol paper
└── privauth/                 # Go implementation
    ├── README.md             # Detailed docs
    ├── go.mod, go.sum
    ├── *.go                  # Library (setup, dissign, batchver, zk_circuit, types, errors)
    └── demo/                 # Demo application
        ├── main.go
        └── go.mod
```

## License

Same license as gnark.
