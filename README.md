# bcrypt

[![Build Status](https://travis-ci.org/Keats/rust-bcrypt.svg)](https://travis-ci.org/Keats/rust-bcrypt)

## Installation
Add the following to Cargo.toml:

```toml
bcrypt = "0.1"
```

## Usage
The crate makes 3 things public: `DEFAULT_COST`, `hash`, `verify`.

```rust
extern crate bcrypt;

use bcrypt::{DEFAULT_COST, hash, verify};

let hashed = match hash("hunter2", DEFAULT_COST) {
    Ok(h) => h,
    Err(_) => panic!()
};

let valid = match verify("hunter2", &hashed) {
    Ok(valid) => valid,
    Err(_) => panic!()
};
```

The cost needs to be an integer between 4 and 31 (see benchmarks to have an idea of the speed for each), the `DEFAULT_COST` is 12.

## Benchmarks
Speed depends on the cost used: the highest the slowest.
Here are some benchmarks to give you some ideas on the cost/speed ratio. Note that I don't go above 14 as it takes too long.

```
test bench_cost_4       ... bench:   1,312,762 ns/iter (+/- 155,397)
test bench_cost_10      ... bench:  80,696,053 ns/iter (+/- 8,290,601)
test bench_cost_default ... bench: 322,494,673 ns/iter (+/- 19,445,864)
test bench_cost_14      ... bench: 1,295,103,136 ns/iter (+/- 83,242,618)
```

## Acknowledgments
This [gist](https://gist.github.com/rgdmarshall/ae3dc072445ed88b357a) for the hash splitting and the null termination.


## Changelog

* 0.1.4: Replace rustc-serialize dependency with bcrypt
* 0.1.3: Fix panic when password > 72 chars
* 0.1.1: make BcryptResult, BcryptError public and update dependencies
* 0.1.0: initial release
