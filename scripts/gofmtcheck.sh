#!/usr/bin/env bash

echo "==> Checking that code complies with gofmt requirements..."

gofmt_files=$(go fmt -mod vendor $(go list ./...))
if [[ -n ${gofmt_files} ]]; then 
    echo 'gofmt needs running on the following files:'
    echo "${gofmt_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi
