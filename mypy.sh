#!/bin/bash

set -e

if [ "$#" -eq 0 ]; then
    # No arguments: check the entire codebase
    targets="ida_colors/ tests/"
else
    # Arguments given: check only those files
    targets="$@"
fi

uv run mypy $targets
