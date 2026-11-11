#!/usr/bin/env sh
# Build a VulnScope MAX + Zeek bundle for a computer with no internet (segmented network/enclave).
#
#   scripts/docker/offline-bundle.sh                 # this computer's architecture
#   scripts/docker/offline-bundle.sh linux/amd64     # most Windows/Linux PCs and servers
#   scripts/docker/offline-bundle.sh linux/arm64     # Apple silicon Macs, ARM servers
#   scripts/docker/offline-bundle.sh linux/amd64 --secret id=ca,src=corp-ca.pem   # extra build flags
#
# Run it where Docker can reach the internet. It writes dist/vulnscope-max-<version>-<arch>/ with
# the image (docker save), the source and compose file, checksums, and LOAD.txt with the steps
# for the other side. Carry that folder across however your enclave allows.
set -eu
cd "$(dirname "$0")/../.."
platform="${1:-}"
[ $# -gt 0 ] && shift
version="$(git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d)"
if [ -z "$platform" ]; then
  case "$(uname -m)" in arm64|aarch64) platform=linux/arm64 ;; *) platform=linux/amd64 ;; esac
fi
arch="${platform#linux/}"
tag="vulnscope-max:${version}"
out="dist/vulnscope-max-${version}-${arch}"
mkdir -p "$out"

echo "Building $tag for $platform ..."
docker buildx build --platform "$platform" --pull --tag "$tag" --tag vulnscope-max:latest \
  --output "type=docker" "$@" .
echo "Saving image ..."
docker save "$tag" vulnscope-max:latest | gzip > "$out/vulnscope-max-image-${arch}.tar.gz"
echo "Packing source ..."
git ls-files -z --cached --others --exclude-standard | tar --null -T - -czf "$out/vulnscope-max-source.tar.gz"
sed "s/@VERSION@/${version}/g; s/@ARCH@/${arch}/g" scripts/docker/LOAD.txt > "$out/LOAD.txt"
( cd "$out" && { sha256sum * 2>/dev/null || shasum -a 256 *; } | grep -v SHA256SUMS > SHA256SUMS )
echo
echo "Bundle ready: $out"
ls -lh "$out"
