#!/bin/bash

set -e

RUFF="uv run ruff"

if [ "$#" -eq 0 ]; then
    # No arguments: check the entire codebase
    targets="ida_colors/ tests/"
else
    # Arguments given: check only those files
    targets="$@"
fi

$RUFF format $targets && $RUFF check --fix $targets && $RUFF check --select I --fix $targets