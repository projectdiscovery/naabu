#!/bin/bash

echo "::group::Build naabu"
rm integration-test naabu 2>/dev/null
cd ../v2/cmd/naabu
go build
mv naabu ../../../integration_tests/naabu
echo "::endgroup::"

echo "::group::Build naabu integration-test"
cd ../integration-test
go build
mv integration-test ../../../integration_tests/integration-test 
cd ../../../integration_tests
echo "::endgroup::"

./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
