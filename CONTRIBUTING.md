# Contributing to bedrock

Thank you for your interest in contributing to `bedrock`!

## Development Environment

1.  **Rust**: Ensure you have the latest stable Rust toolchain installed via [rustup](https://rustup.rs/).
2.  **Formatting**: We use `rustfmt` to ensure consistent code style.
    ```bash
    cargo fmt
    ```
3.  **Linting**: We use `clippy` to catch common mistakes.
    ```bash
    cargo clippy -- -D warnings
    ```

## Running Tests

Run the full test suite, including unit and integration tests:

```bash
cargo test
```

## Test Coverage

To verify test coverage locally, we use `cargo-tarpaulin`.

1.  Install `cargo-tarpaulin`:
    ```bash
    cargo install cargo-tarpaulin
    ```
2.  Run coverage:
    ```bash
    cargo tarpaulin --out Html
    ```
    This will generate a `tarpaulin-report.html` file in the root directory which you can open in your browser.

## Pull Requests

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b my-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-feature`).
5.  Open a Pull Request.

Please ensure all tests pass and that you've added new tests for any new functionality.
