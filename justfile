set dotenv-load

# format, clippy and tests
default: fmt clippy test

# testing, filters available
test *FILTER:
    @echo "Running tests with filter: '{{FILTER}}'"
    cargo nextest run {{FILTER}}

# format and clippy
check: fmt clippy

# format
fmt:
    cargo +nightly fmt

# clippy for code and tests
clippy *OPTIONS:
    cargo clippy {{OPTIONS}}
    cargo clippy --tests {{OPTIONS}}

shear:
    cargo +nightly shear --expand --fix

doc:
    cargo doc --open --no-deps --document-private-items

build-linux-x86:
    cargo zigbuild --release --target x86_64-unknown-linux-gnu
