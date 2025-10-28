# FerroHSM Agent Guidelines

## Build/Lint/Test Commands
- **Build all crates**: `cargo build`
- **Build specific crate**: `cargo build -p hsm-core` (or hsm-server, hsm-cli)
- **Run all tests**: `cargo test`
- **Run single test**: `cargo test test_name` or `cargo test -- --exact test_name`
- **Run tests for specific crate**: `cargo test -p hsm-core`
- **Run end-to-end tests**: `./scripts/e2e_test.sh`
- **Lint**: `cargo clippy`
- **Format**: `cargo fmt`

## Code Style Guidelines
- **Imports**: Group std imports first, then external crates, then local crates. Use explicit imports over glob imports.
- **Formatting**: Use `cargo fmt` for consistent formatting. Follow standard Rust formatting conventions.
- **Types**: Use strong typing with enums for constrained values. Implement Serialize/Deserialize for API types.
- **Naming**: snake_case for functions/variables, PascalCase for types/enums, SCREAMING_SNAKE_CASE for constants.
- **Error handling**: Use `thiserror` for custom error types. Return `Result<T, HsmError>` for fallible operations.
- **Documentation**: Add comprehensive doc comments for public APIs using `//!` for modules and `///` for items.
- **Async**: Use `tokio` runtime. Prefer async traits with `async-trait` crate.
- **Security**: Never log sensitive data. Use constant-time operations for crypto. Validate all inputs.