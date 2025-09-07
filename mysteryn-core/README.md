# Mysteryn Core

This crate provides the core traits and functions used by the `mysteryn-crypto` and `mysteryn-keys` crates. It also includes traits for implementing custom key algorithms.

See the [`mysteryn-crypto` README](../mysteryn-crypto/README.md) for a full description of the project.

## Tests and benches

```bash
cargo test
```

Cargo stands benches as tests, so need `--test`. As the memory allocator is
global, need to run in one thread. To distinquish benches, their names start
with "bench":

```bash
cargo bench -- --test --test-threads=1 -q bench
```

or

```bash
cargo b
```

## License

Licensed under the [Ethical Use License v1.0](./LICENSE.md).
