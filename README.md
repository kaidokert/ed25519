OUERTANI Mohamed Hachem

# Requirements

- A rust environment (cargo and rustc). You can use rustup for a simple set-up.

# How to compile

- For release : `make all`
- To run code : `cargo run --bin=[keygen|sign|verify] arg1 arg2 arg3`
- There are test units in lib.rs for most functions used.
- Alternatively : you can run the programs found under the folder `release` after having done `make all`


# For cleanup

- Run `make clean`
