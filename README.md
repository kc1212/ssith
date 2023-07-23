# SSiTH: Subset Sum in the Head

## Build and test

```
cargo test
cargo run --example simulation
```
Use the `--release` flag for better performance.

The simulation example prints 
the prover's internal state,
which can be piped to a file for inspection,
i.e., `cargo run --example simulation > prover_state.txt`.

## Internal

- At the moment only 128-bits of security is supported.
- All PRGs are based on AES-128 with counter mode.
Other than the seed, the PRG also takes an IV,
which is a hash of the witness-instance pair
in our implementation.
- All the hash functions are implemented using SHA3-256.
Appropriate care is taken to ensure there are no
domain separation issues.

## Future work

- [ ] Implement and test the rest of the protocol.
- [ ] Consider using `GenericArray`, the consts in `consts.rs`
would become const generics.
- [ ] Support 256-bits of security.