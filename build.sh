#!/usr/bin/env bash

set -o nounset
set -o errexit
set -o pipefail

# Check for required external programs. If any are missing output a list of all
# requirements and then exit.
function check_dependencies {
  required_tools="pip python zip"
  for tool in $required_tools; do
    if [ -z "$(command -v "$tool")" ]; then
      echo "This script requires the following tools to run:"
      for item in $required_tools; do
        echo "- $item"
      done
      exit 1
    fi
  done
}

check_dependencies

PY_VERSION="${BUILD_PY_VERSION:-3.8}"
# Use the current directory name
FILE_NAME="${BUILD_FILE_NAME:-${PWD##*/}}"

###
# Define the name of the Lambda zip file being produced.
###
ZIP_FILE="${FILE_NAME}.zip"

###
# Set up the Python virtual environment.
# We use --system-site-packages so the venv has access to the packages already
# installed in the container to avoid duplicating what will be available in the
# lambda environment on AWS.
###
VENV_DIR="/venv"
python -m venv --system-site-packages "$VENV_DIR"

# Here shellcheck complains because it can't follow the dynamic path.
# The path doesn't even exist until runtime, so we must disable that
# check.
#
# shellcheck disable=1090
source "$VENV_DIR/bin/activate"

###
# Upgrade pip.
###
pip install --upgrade pip

###
# Install local findings data import (fdi) module and requirements.
###
pip install --requirement requirements.txt

###
# Leave the Python virtual environment.
#
# Note that we have to turn off nounset before running deactivate,
# since otherwise we get an error that states "/venv/bin/activate:
# line 31: $1: unbound variable".
###
set +o nounset
deactivate
set -o nounset

###
# Set up the build directory.
###
BUILD_DIR=/build

###
# Copy all packages, including any hidden dotfiles. Also copy the
# local fdi package and the lambda handler.
###
cp --recursive --no-target-directory "$VENV_DIR/lib/python$PY_VERSION/site-packages/" "$BUILD_DIR"
cp --recursive --no-target-directory "$VENV_DIR/lib64/python$PY_VERSION/site-packages/" "$BUILD_DIR"
cp --recursive fdi "$BUILD_DIR"
cp lambda_handler.py "$BUILD_DIR"

###
# Zip it all up.
###
OUTPUT_DIR="/output"
if [ ! -d "$OUTPUT_DIR" ]; then
  mkdir "$OUTPUT_DIR"
fi

if [ -e "$OUTPUT_DIR/$ZIP_FILE" ]; then
  rm "$OUTPUT_DIR/$ZIP_FILE"
fi

cd $BUILD_DIR
# Recursively (-r) add the current directory to the specified output filename
# using maximum compression (-9) without informational message (-q).
zip -rq9 "$OUTPUT_DIR/$ZIP_FILE" .
