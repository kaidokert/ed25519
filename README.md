# Requirements

- A rust environment (cargo and rustc). You can use rustup for a simple set-up.

# How to compile

- For release : `make all`
- To run code : `cargo run --bin=[keygen|sign|verify] arg1 arg2 arg3`
- Unfortunately I could not get sign and verify to work as of yet ... There are tests however in the file lib.rs which would be interesting to look at.

# For cleanup

- Run `make clean`
