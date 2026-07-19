# AVR footprint campaign

Install the shared host tool and run the declarative baseline/verification
campaign:

```sh
cargo install krabi-caliper --features cli
cargo krabi-caliper run ed25519-avr
```

For local toolkit development, install with
`cargo install --path ../../krabi-caliper --features cli --force`. The
campaign uses the consumer-owned `nightly-2025-11-01` pin and writes ELF,
protocol, stack, timing, and baseline-delta reports below
`target/krabi-caliper/`.
