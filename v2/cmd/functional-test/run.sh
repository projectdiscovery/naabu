#!/bin/bash

echo 'Building functional-test binary'
go build

echo 'Building NAABU binary from current branch'
go build -o naabu_dev ../naabu

echo 'Installing latest release of NAABU'
GO111MODULE=on go build -v github.com/projectdiscovery/naabu/v2/cmd/naabu

echo 'Starting NAABU functional test'
./functional-test -main ./naabu -dev ./naabu_dev -testcases testcases.txt
