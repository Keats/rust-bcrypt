Bare metal build test
==

Use by CI to ensure that `bcrypt` with `no-default-features` can work
in a bare metal program. The platform doesn't have any of
`std`, `alloc`, `getrandom`.

Based on https://github.com/rust-embedded/cortex-m-quickstart
under a MIT license.
