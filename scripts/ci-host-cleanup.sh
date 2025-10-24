#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# This helper script is used in CI to free disk space on the runner
#
echo "Disk usage before cleanup:"
df -h

echo "Removing unnecessary packages"
packages=(
google-chrome-stable microsoft-edge-stable firefox
azure-cli google-cloud-cli kubectl podman skopeo buildah snapd
temurin-8-jdk temurin-11-jdk temurin-17-jdk temurin-21-jdk
dotnet-sdk-8.0 dotnet-runtime-8.0 aspnetcore-runtime-8.0
aspnetcore-targeting-pack-8.0 netstandard-targeting-pack-2.1-8.0
dotnet-targeting-pack-8.0
llvm-16-dev llvm-17-dev llvm-18-dev
clang-tools-16 clang-tools-17 clang-tools-18
clang-tidy-16 clang-tidy-17 clang-tidy-18
)
for pkg in "${packages[@]}"; do
	echo -n "$pkg is "
	if dpkg-query -W -f='${Package}\n' $pkg 2>/dev/null | grep -q .; then
		to_remove="$to_remove $pkg"
		found=1
	else
		echo -n "not "
	fi
	echo "installed"
done
if [ "$found" ]; then
	sudo apt-get remove -y --purge --allow-change-held-packages \
		--allow-remove-essential --no-install-recommends \
		$to_remove || true
fi
sudo apt-get autoremove -y || true
sudo apt-get clean || true

echo "Removing more unnecessary files"
sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/hostedtoolcache

echo "Disk usage after cleanup:"
df -h
