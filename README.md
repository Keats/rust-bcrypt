# bcrypt

[![Build Status](https://travis-ci.org/Keats/rust-bcrypt.svg)](https://travis-ci.org/Keats/rust-bcrypt)
[![Documentation](https://docs.rs/bcrypt/badge.svg)](https://docs.rs/bcrypt)

## Installation
Add the following to Cargo.toml:

```toml
bcrypt = "0.2"
```

## Usage
The crate makes 3 things public: `DEFAULT_COST`, `hash`, `verify`.

```rust
extern crate bcrypt;

use bcrypt::{DEFAULT_COST, hash, verify};

let hashed = hash("hunter2", DEFAULT_COST)?;
let valid = verify("hunter2", &hashed)?;
```

The cost needs to be an integer between 4 and 31 (see benchmarks to have an idea of the speed for each), the `DEFAULT_COST` is 12.

## Benchmarks
Speed depends on the cost used: the highest the slowest.
Here are some benchmarks on my 4 years old laptop to give you some ideas on the cost/speed ratio. 
Note that I don't go above 14 as it takes too long.

```
test bench_cost_4       ... bench:   1,197,414 ns/iter (+/- 112,856)
test bench_cost_10      ... bench:  73,629,975 ns/iter (+/- 4,439,106)
test bench_cost_default ... bench: 319,749,671 ns/iter (+/- 29,216,326)
test bench_cost_14      ... bench: 1,185,802,788 ns/iter (+/- 37,571,986)
```

## Acknowledgments
This [gist](https://gist.github.com/rgdmarshall/ae3dc072445ed88b357a) for the hash splitting and the null termination.

## Changelog

* 0.2.0: replace rust-crypto with blowfish, use some more modern Rust things like `?` and handle more errors
* 0.1.6: update rand and base64 deps
* 0.1.5: update lazy-static to 1.0
* 0.1.4: Replace rustc-serialize dependency with bcrypt
* 0.1.3: Fix panic when password > 72 chars
* 0.1.1: make BcryptResult, BcryptError public and update dependencies
* 0.1.0: initial release
