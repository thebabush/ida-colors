#!/bin/bash

# Work around stupid implementation
# See: https://github.com/microsoft/vscode-mypy/blob/8cb6bcadc6798e4449eab864b3f0481f677fcb1a/bundled/tool/lsp_server.py#L634

unset MYPYPATH

uv run mypy "$@"