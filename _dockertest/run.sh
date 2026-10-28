#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${NAABU_DOCKERTEST_IMAGE:-naabu-dockertest}"

docker build -f "${repo_root}/_dockertest/Dockerfile" -t "${image}" "${repo_root}"
docker run --rm --privileged "${image}" bash -c '
set -euo pipefail

python3 /src/_dockertest/server.py 18080 18443 &
fixture_pid=$!
trap "kill ${fixture_pid} 2>/dev/null || true" EXIT

ready=false
for _ in $(seq 1 50); do
	if (echo >/dev/tcp/127.0.0.1/18080) 2>/dev/null; then
		ready=true
		break
	fi
	sleep 0.1
done
if [[ "${ready}" != true ]]; then
	echo "fixture did not become ready" >&2
	exit 1
fi

actual="$(
	/usr/local/bin/naabu \
		-host 127.0.0.1 \
		-p 18080,18443,19999 \
		-s s \
		-tw 4 \
		-silent \
		-no-stdin |
	sort
)"
expected="$(printf "127.0.0.1:18080\n127.0.0.1:18443")"

if [[ "${actual}" != "${expected}" ]]; then
	printf "unexpected SYN results\nexpected:\n%s\nactual:\n%s\n" "${expected}" "${actual}" >&2
	exit 1
fi
printf "%s\n" "${actual}"
'
