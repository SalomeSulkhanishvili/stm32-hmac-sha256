# Rust Implementation: HMAC-SHA256 on STM32

Minimal `no_std` Rust implementation that **signs and verifies MAVLink v2 messages using HMAC-SHA256**, targeting both a QEMU-simulated Cortex-M7 and a real STM32 board. 

## Overview

MAVLink v2 defines an optional packet-signing mechanism. The signature appended to each frame is the first 6 bytes of `HMAC-SHA256(secret_key, signing_bytes)`, where `signing_bytes` is the concatenation of the MAVLink header, payload, CRC, link-id, and a 48-bit timestamp.

This project implements:

- **`sign_frame`** - computes the CRC, sets the `SIGNED_FLAG`, and appends the truncated HMAC tag.
- **`verify_frame`** - re-derives the HMAC, compares it in constant time, and enforces replay-protection (10-second window + monotonic timestamp).

Everything runs without a heap (`no_std`, no `alloc`). All variable-length buffers use [`heapless::Vec`](https://docs.rs/heapless) with compile-time capacity bounds.

## Repository Structure

`mavlink/` is a standalone `no_std` library that contains the full sign and verify implementation. `chips/` holds one crate per MCU - each crate is an independent binary that imports `mavlink` and can be flashed or simulated independently. Adding support for a new microcontroller means adding a new crate under `chips/` without touching the core library.

## Libraries Used

| Crate | Version | Role |
|---|---|---|
| [`hmac`](https://docs.rs/hmac) | 0.13 | HMAC construction (wraps any `Digest`) |
| [`sha2`](https://docs.rs/sha2) | 0.11 | SHA-256 digest, pure-Rust, `no_std` |
| [`subtle`](https://docs.rs/subtle) | 2 | Constant-time byte comparison (`ct_eq`) |
| [`heapless`](https://docs.rs/heapless) | 0.9 | Stack-allocated `Vec` (no allocator needed) |
| [`defmt`](https://docs.rs/defmt) | 1.0.1 | Efficient embedded logging |
| [`cortex-m-rt`](https://docs.rs/cortex-m-rt) | 0.7 | Reset handler and entry point |
| [`cortex-m`](https://docs.rs/cortex-m) | 0.7.6 | Low-level Cortex-M intrinsics |
| [`embedded-hal`](https://docs.rs/embedded-hal) | 1.0 | Hardware abstraction traits |
| `defmt-semihosting` / `defmt-rtt` | - | Log transport (QEMU semihosting / RTT on real hardware) |
| `panic-semihosting` / `panic-probe` | - | Panic handler per target |
| [`critical-section`](https://docs.rs/critical-section) | 1.0 | Portable critical section for timestamp update |

All crypto crates are used with `default-features = false` to strip any `std`-dependent code paths.

## Hardware Targets

### QEMU (Cortex-M7, simulated)

Runs on the MPS2-AN500 machine model with a Cortex-M7 CPU:

```
qemu-system-arm -cpu cortex-m7 -machine mps2-an500 -nographic \
  -semihosting-config enable=on,target=native -kernel <elf>
```

Target triple: `thumbv7em-none-eabihf`

```bash
cd chips/qemu-m7
cargo run --release
```

### STM32C092RC (real hardware)

Tested on the **STM32C092RC** (Cortex-M0+, 256 KB flash, 30 KB RAM), flashed via `probe-rs`:

```bash
cd chips/stm32c092rc
cargo run --release
```

## Running Tests

The `mavlink` library has a host-side test suite covering all sign/verify paths:

```bash
cargo test -p mavlink
```

All 17 tests run on the host (no QEMU required). They cover successful sign-and-verify, key errors, unknown message IDs, payload/signature tampering, CRC mismatch, timestamp ordering, and replay prevention.

## Running the Demo

Both targets execute the same sign-then-verify scenario:

1. Construct a 3-byte HEARTBEAT payload.
2. Call `sign_frame` - sets `INC_FLAGS = 0x01`, writes CRC, computes and stores the 6-byte HMAC tag.
3. Call `verify_frame` with a later timestamp - checks the flag, CRC, HMAC (constant-time), timestamp order, and replay window.
4. Log `"Verification passed"` via defmt.

Expected output (QEMU semihosting):

```
INFO  MAVLink signing demo
INFO  Frame signed
INFO  Verification passed
```

## Design Decisions

### No heap, no allocator

`heapless::Vec<u8, N>` is used for the payload (`MAX_PAYLOAD_SIZE = 255`) and the serialised frame (`MAX_FRAME_SIZE = 280`). These live on the stack and have a fixed upper bound known at compile time, which is safe on targets with as little as 30 KB of RAM.

### Streaming HMAC - no intermediate buffer

`feed_signing_bytes` calls `mac.update()` in wire order (header → payload → CRC → link-id → timestamp) without first assembling the full frame into a temporary buffer. HMAC processes input incrementally, so this is semantically identical to a single large `update` call but avoids allocating a 280-byte scratch buffer.

### Constant-time comparison

`subtle::ConstantTimeEq` is used to compare the computed and received HMAC tags. A naive `==` or `memcmp` would short-circuit on the first differing byte, leaking timing information about how many bytes of a forged tag are correct - a classic side-channel. `subtle` prevents this at the cost of zero additional memory.

### Replay protection

`verify_frame` enforces two independent replay guards:

- **Window check** - rejects frames whose timestamp is more than 1,000,000 MAVLink units (10 seconds) in the past.
- **Monotonic check** - inside a `critical_section`, rejects any frame whose timestamp is not strictly greater than the last accepted one and updates `MavLinkState` atomically. This prevents an attacker from replaying a recently valid frame within the window.

### Truncated signature (6 bytes)

The MAVLink v2 specification mandates exactly 6 bytes for the signature field. The full 32-byte HMAC output is computed but only the first 6 bytes are stored. This provides 48-bit security against forgery - adequate for authenticated telemetry while keeping the per-frame overhead small (13 bytes total: 1 link-id + 6 timestamp + 6 signature).

### CRC-extra

Each MAVLink message type has a `crc_extra` byte that is mixed into the CRC. A small lookup table (`crc_extra_for`) covers the message IDs used in tests. In a production firmware this table would be generated from the MAVLink XML dialect.

## Memory Usage

Flash = `.vector_table` + `.text` + `.rodata` + `.data` (`.data` initializers live in flash on Cortex-M and are copied to RAM at boot). Static RAM = `.data` + `.bss` + `.uninit`.

To reproduce, run from the relevant chip directory:

```bash
# dev (with logging)
cargo size -- -A

# release / release-deploy (without logging)
cargo size --release --no-default-features -- -A
cargo size --profile release-deploy --no-default-features -- -A
```

### QEMU Cortex-M7 (`chips/qemu-m7`)

Device: 1 MB Flash, 512 KB RAM. QEMU uses semihosting so no RTT ring buffer, but stripping the `logging` feature still removes the defmt/semihosting code from flash.

| Profile | Features | Flash | Flash % | Static RAM | Static RAM % |
|---|---|---|---|---|---|
| `dev` | `logging` | 83.9 KB | 8.2% | 16 B | <0.1% |
| `release` | `--no-default-features` | 12.2 KB | 1.2% | 0 B | 0% |
| `release-deploy` | `--no-default-features` | 10.8 KB | 1.1% | 0 B | 0% |

### STM32C092RC (`chips/stm32c092rc`)

Device: 256 KB Flash, 30 KB RAM. `defmt-rtt` + `panic-probe` are behind the `logging` feature (on by default). Release builds pass `--no-default-features` to drop the 1 KB RTT ring buffer and switch to `panic-halt`.

| Profile | Features | Flash | Flash % | Static RAM | Static RAM % |
|---|---|---|---|---|---|
| `dev` | `logging` | 68.1 KB | 26.6% | 1.1 KB | 3.5% |
| `release` | `--no-default-features` | 15.1 KB | 5.9% | 0 B | 0% |
| `release-deploy` | `--no-default-features` | 12.3 KB | 4.8% | 0 B | 0% |

Static RAM is 0 B in release because all program state (`MavLinkFrame`, `MavLinkState`, buffers) lives on the stack. The full RAM is available to the stack at runtime.

**Profile settings** (workspace `Cargo.toml`):

| Profile | `opt-level` | `lto` | `debug` | `strip` | `panic` |
|---|---|---|---|---|---|
| `dev` | 0 | off | full | no | `abort` |
| `release` | `s` (size) | thin | symbols | no | `abort` |
| `release-deploy` | `z` (min size) | thin | none | yes | `abort` |

`panic = "abort"` is set in all profiles - there is no unwinding machinery, which eliminates the unwind tables from the binary.

## Contributors

- Salome Sulkhanishvili
