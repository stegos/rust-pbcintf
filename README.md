# rust-libpbc

Rust bindings for PBC library

For building requires PBC and GMP libraries installed in system default locations.

On MacOS this can be done using `brew`:

```shell
brew install pbc gmp
```

## Build and test

```shell
cargo build
cargo test
```

## Run `echo-test` example

```shell
cargo run --example echo-test
```

Example sources are located in [here](examples/echo-test.rs)
