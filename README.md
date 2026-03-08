### ed25519 heapless fork

This is a fork of `ed25519` crate that is ported to microcontrollers. It's tested on 8-bit AVR and Cortex-M

It only does signature verifications right now ( e.g. bootloaders ) as constant time ops and private key handling requires constant-time ops.
