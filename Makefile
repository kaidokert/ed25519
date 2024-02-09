default: all

zip:
	rm -f mohamed.ouertani.td4.zip
	zip -r mohamed.ouertani.td4.zip . -i README.md src/\* Makefile Cargo.toml

all:
	cargo build --release

clean:
	cargo clean
	rm -rf release/