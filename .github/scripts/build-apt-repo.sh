#!/bin/sh
# Builds the Helios APT repository in REPO_DIR from the packages already in REPO_DIR/pool (the
# published ones, synced from S3) and the new .deb files, and signs it with the GPG key KEY_ID.
#
# Usage: build-apt-repo.sh REPO_DIR KEY_ID DEB...
#
# Layout (one suite, "stable", component "main"):
#   pool/main/h/helios/<name>_<version>_<arch>.deb   packages, never changed once published
#   dists/stable/main/binary-<arch>/Packages[.gz]    the index of every package in the pool
#   dists/stable/{Release,Release.gpg,InRelease}     the signed release file APT checks
#   keys/helios-archive-keyring.asc                  the public key, for devices' signed-by
#
# The Release file's Origin and Label ("Helios") are what the package's unattended-upgrades
# config (dist/debian/52helios-unattended-upgrades) matches. Needs apt-ftparchive (apt-utils),
# gpg and gzip. Publishing order (packages first, InRelease last) is the caller's job.
set -eu

if [ $# -lt 3 ]; then
    echo "usage: $0 REPO_DIR KEY_ID DEB..." >&2
    exit 2
fi
repo=$1
key=$2
shift 2

suite=stable
component=main
pool=pool/$component/h/helios

mkdir -p "$repo/$pool" "$repo/keys"
for deb in "$@"; do
    name=$(basename "$deb")
    if [ -e "$repo/$pool/$name" ] && ! cmp -s "$deb" "$repo/$pool/$name"; then
        echo "$name is already published with different contents; bump the version" >&2
        exit 1
    fi
    cp "$deb" "$repo/$pool/$name"
done

cd "$repo"
rm -rf "dists/$suite"
archs=$(for deb in "$pool"/*.deb; do dpkg-deb -f "$deb" Architecture; done | sort -u)
for arch in $archs; do
    dir=dists/$suite/$component/binary-$arch
    mkdir -p "$dir"
    apt-ftparchive --arch "$arch" packages "$pool" >"$dir/Packages"
    gzip -9 -n -k "$dir/Packages"
done

apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=Helios \
    -o APT::FTPArchive::Release::Label=Helios \
    -o APT::FTPArchive::Release::Suite=$suite \
    -o APT::FTPArchive::Release::Codename=$suite \
    -o "APT::FTPArchive::Release::Architectures=$(echo "$archs" | tr '\n' ' ' | sed 's/ $//')" \
    -o APT::FTPArchive::Release::Components=$component \
    -o "APT::FTPArchive::Release::Description=Helios on-device agent" \
    release "dists/$suite" >"dists/$suite/Release.new"
mv "dists/$suite/Release.new" "dists/$suite/Release"

gpg --batch --yes --local-user "$key" --armor --detach-sign \
    --output "dists/$suite/Release.gpg" "dists/$suite/Release"
gpg --batch --yes --local-user "$key" --clearsign \
    --output "dists/$suite/InRelease" "dists/$suite/Release"
gpg --batch --yes --armor --export "$key" >keys/helios-archive-keyring.asc

echo "built $repo: $(echo "$archs" | tr '\n' ' ')"
