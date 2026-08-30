# HytaleRS

An experimental Hytale server implementation written in Rust.

HytaleRS explores how a modular, asynchronous game-server architecture can be built with Rust's type system and concurrency model. The project currently focuses on protocol handling, QUIC networking, connection state transitions, configuration, events, and asset loading.

> [!WARNING]
> HytaleRS is an early-stage research project. It is incomplete, is not ready for production use, and cannot currently replace the official Hytale server.

## Current work

- Async QUIC networking with `quinn`, `rustls`, and `tokio`
- Bidirectional connection handling with timeouts and rate limiting
- State-based packet handlers for connection and setup stages
- Typed packet encoding and decoding
- Packet registration and metadata through procedural macros
- Synchronous and asynchronous event handlers with priorities
- JSON configuration with Serde
- Asset-pack discovery, registration, and loading
- Structured logging and command-line options

Several major systems—including gameplay, worlds, entities, persistence, and the plugin runtime—are still incomplete or not implemented.

## Architecture

HytaleRS is organized as a Cargo workspace:

| Crate | Purpose |
| --- | --- |
| `server` | Server lifecycle, networking, authentication, assets, configuration, events, and commands |
| `protocol` | Packet definitions, layouts, codecs, encoders, decoders, and protocol objects |
| `macros` | Procedural macros used to generate protocol-related implementations and registration metadata |

The network layer accepts QUIC connections and moves each connection through dedicated packet-handler stages. Handlers can continue processing, transition to a new stage, or terminate the connection. Protocol types remain separate from server behavior so packet serialization can evolve independently.

## Reading the code

Start with [server/src/main.rs](server/src/main.rs) for the boot sequence, then follow [server/src/net](server/src/net) for connections and packet-handler transitions. The [protocol/src](protocol/src) directory contains the wire-format types, while [macros/src](macros/src) contains code generation.

Configuration is loaded from `config.json` in the working directory and saved with defaults by [server/src/config.rs](server/src/config.rs). See [server/src/utils/options.rs](server/src/utils/options.rs) for command-line declarations; some options describe planned behavior that is not fully wired up yet.

## Technology

- Rust 2024 edition
- Tokio
- Quinn / QUIC
- Rustls
- Serde and Serde JSON
- Clap
- AHash and parking_lot
- Inventory-based packet registration

## Building

A recent stable Rust toolchain with Rust 2024 edition support is required.

```bash
git clone https://github.com/7azeemm/HytaleRS.git
cd HytaleRS
cargo check --locked --workspace
cargo build --locked --workspace
```

Running the server additionally requires compatible game assets and development data that are not distributed in this repository. Some development paths and protocol behavior are still being refactored, so a clean build does not imply a playable server.

### Runtime caveats

- The asset option defaults to `../HytaleAssets` and accepts an existing directory or ZIP path. Supply only assets you are authorized to use.
- The network manager currently binds directly to `[::]:5520`; the declared `--bind` option does not yet control that listener.
- Authentication and connection setup remain works in progress. Development builds should not be exposed as public servers.
- Declared world, backup, migration, and plugin options do not mean those systems are complete.

A successful compile is only a development check, not evidence of client compatibility or playable gameplay.

## Project status

The current goal is to establish reliable foundations before implementing higher-level gameplay:

- [x] Cargo workspace and crate separation
- [x] Core packet codec infrastructure
- [x] QUIC listener and connection lifecycle
- [x] Handler-driven protocol stages
- [x] Configuration and event foundations
- [x] Initial asset pipeline
- [ ] Complete authentication flow
- [ ] Complete connection and setup sequence
- [ ] World and entity systems
- [ ] Persistent player and world storage
- [ ] Functional plugin system
- [ ] Compatibility and performance testing

APIs and internal structures may change substantially while the project is under development.

## Motivation

This project is an exploration of systems programming for a large, stateful game server. Its design emphasizes explicit state transitions, strongly typed protocol data, modular boundaries, asynchronous I/O, and predictable resource use.

## Contributing

The repository is currently experimental. Issues and focused pull requests are welcome, but please discuss large architectural changes before investing significant work.

## Disclaimer

HytaleRS is an independent, unofficial project and is not affiliated with, endorsed by, or sponsored by Hypixel Studios or Riot Games. Hytale and related names and assets belong to their respective owners. No proprietary game assets are included in this repository.

No license is currently granted for reuse or redistribution of this repository's source code.
