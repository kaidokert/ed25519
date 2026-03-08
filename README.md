### ed25519 heapless fork

This is a fork of the `ed25519` crate, ported to microcontrollers. It's tested on 8-bit AVR and Cortex-M.

It only does signature verification right now (e.g., bootloaders), as private key handling requires constant-time operations.
