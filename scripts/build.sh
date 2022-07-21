#!/usr/bin/env bash

TOOL=vault-plugin-secrets-azure
#
# This script builds the application from source for multiple platforms.
set -e

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd "$DIR"

# Set build tags
BUILD_TAGS="${BUILD_TAGS}:-${TOOL}"

# Get the git commit
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

GOPATH=${GOPATH:-$(go env GOPATH)}
case $(uname) in
    CYGWIN*)
        GOPATH="$(cygpath $GOPATH)"
        ;;
esac

# Delete the old dir
echo "==> Removing old directory..."
rm -f bin/*
rm -rf pkg/*
mkdir -p bin/

# Build!
echo "==> Building..."
go build \
    -ldflags "${LD_FLAGS} -X github.com/hashicorp/${TOOL}/version.GitCommit='${GIT_COMMIT}${GIT_DIRTY}'" \
    -o "bin/${TOOL}" \
    -tags="${BUILD_TAGS}" \
    ./cmd/$TOOL

# Done!
echo
echo "==> Results:"
ls -hl bin/
