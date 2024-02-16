default: all

zip:
	rm -f mohamed.ouertani.td5.zip
	zip -r mohamed.ouertani.td5.zip . -i README.md src/\* Makefile Cargo.toml

all:
	cargo build --release
	mkdir -p release
	rm -f release/poly1305-check release/poly1305-gen release/chacha20
	cp target/release/keygen release/keygen
	cp target/release/sign release/sign
	cp target/release/verify release/verify

clean:
	cargo clean
	rm -rf release/