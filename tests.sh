#!/bin/sh

set -e

cd "$(dirname "$0")"
python3 gen_test_vectors.py
mypy --no-error-summary reference.py
python3 reference.py