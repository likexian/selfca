#!/bin/bash

arch=386
for os in linux windows; do
    echo "Building selfca-$os-$arch..."
    GOOS=$os GOARCH=$arch go build -trimpath -ldflags '-w -s' -o selfca
    zip selfca-$os-$arch.zip selfca
    rm -rf selfca
done

arch=amd64
for os in linux windows darwin; do
    echo "Building selfca-$os-$arch..."
    GOOS=$os GOARCH=$arch go build -trimpath -ldflags '-w -s' -o selfca
    zip selfca-$os-$arch.zip selfca
    rm -rf selfca
done
