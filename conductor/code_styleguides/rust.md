# Rust Style Guide

## General Principles
- **Safety First:** Leverage Rust's type system and ownership model to ensure memory safety. Use `unsafe` only when absolutely necessary and document the safety requirements.
- **Idiomatic Rust:** Follow the conventions established in the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- **Performance:** Be mindful of allocations and prefer zero-cost abstractions where appropriate.

## Formatting
- **rustfmt:** All code must be formatted with the default `rustfmt` settings.
- **Line Length:** Prefer a maximum line length of 100 characters.

## Linting
- **clippy:** All code must pass `cargo clippy` without warnings (or with explicitly justified `allow` attributes).

## Naming Conventions
- **Crates:** `snake_case`
- **Modules:** `snake_case`
- **Types (Structs, Enums, Traits):** `PascalCase`
- **Functions & Methods:** `snake_case`
- **Variables:** `snake_case`
- **Constants & Statics:** `SCREAMING_SNAKE_CASE`

## Error Handling
- **Prefer `Result`:** Use `Result<T, E>` for recoverable errors.
- **Custom Error Types:** Implement custom error types using `thiserror` or `anyhow` as appropriate for the crate.
- **Panic Sparingly:** Use `panic!`, `unwrap()`, and `expect()` only in tests or for truly unrecoverable situations where the program state is corrupted.

## Documentation
- **Doc Comments:** Use `///` for documentation comments on public items.
- **Examples:** Include `doc-tests` or usage examples for public APIs where possible.
