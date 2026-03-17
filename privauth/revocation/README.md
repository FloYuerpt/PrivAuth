# Revocation

Credential revocation verification system based on zk-SNARK, implemented with gnark and BN254 curve.

## Project Structure

```
revocation-main/
├── cmd/
│   └── revocation/          # main executable
│       ├── main.go           # entry point and flow
│       ├── revocation.go     # main circuit (MyCircuit)
│       ├── math.go           # crypto utilities (curve ops, hashing)
│       ├── accumulator_low.go # accumulator circuit
│       └── accumulator_up.go # aggregate verification circuit
├── internal/
│   └── curvebench/          # emulated curve/field constraint benchmark
│       ├── curve.go
│       └── field.go
├── go.mod
├── go.sum
└── README.md
```

## Requirements

- Go 1.21+
- gnark v0.10.0
- gnark-crypto v0.13.0

## Build and Run

```bash
# build
go build -o revocation ./cmd/revocation/

# run
./revocation
```

## Circuit Parameters

- `m = 32`: number of accumulators
- `k = 100`: number of IDs per accumulator
- `n = 5`: number of issuers

## Benchmark

Run emulated curve/field constraint count benchmarks:

```go
import "revocation/internal/curvebench"

curvebench.TestAllEmulatedCurve()
curvebench.TestAllEmulatedField()
```
