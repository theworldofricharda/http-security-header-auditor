# Justfile — task runner. Install `just`: https://github.com/casey/just
# List recipes:            just
# Run the auditor:         just run -- https://example.com
# Run the test suite:      just test
# Format with black:       just format

default:
    @just --list

install:
    pip install -e ".[dev]"

test:
    pytest -v

run *ARGS:
    python secheader_audit.py {{ARGS}}

format:
    pip install black --quiet
    black secheader_audit.py test_secheader_audit.py

lint:
    pip install ruff --quiet
    ruff check secheader_audit.py test_secheader_audit.py
