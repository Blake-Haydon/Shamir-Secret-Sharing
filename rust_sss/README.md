# Rust implementation of Shamir's Secret Sharing Scheme

## Run

This will run the secret sharing scheme over the prime field GF($2^{31} - 1$) with 5 shares and a secret of 123456789.

```bash
cargo run --release
```

The output should look like this:

```bash
Share 1: (1, 904317239)
Share 2: (2, 494301095)
Share 3: (3, 1040892004)
Share 4: (4, 396606319)
Share 5: (5, 708927687)
Reconstructed Secret: 123456789
```

## Parameters

The parameters below can be changed in `src/main.rs` to test different values.
The default values are:

```rust
const NUM_SHARES: usize = 5;
const NUM_THRESHOLD: usize = 3;
const SECRET: u32 = 123456789;
```
