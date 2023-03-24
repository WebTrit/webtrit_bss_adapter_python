#!/bin/sh

echo Running with $@
# test localhost:8080 by default
SERVER="local"

# Check if a command-line parameter was provided
if [ $# -gt 0 ]; then
    SERVER="$1"
fi
export SERVER

pytest -v "$@" /tests/