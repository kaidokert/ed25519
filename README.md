# Requirements

- A rust environment (cargo and rustc). You can use rustup for simple set-up.

# How to compile

- For release : `make all`
- To run code : `cargo run m [u]`
- to test xADD, xDBL and ladder all work, defined in src/lib.rs. : do `cargo test --package x22519 --lib -- elliptic::tests::test_ladder --exact --nocapture`.

# For cleanup

- Run `make clean`
