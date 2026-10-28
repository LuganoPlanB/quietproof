---
title: Linux binary releases
description: Semantic release versioning and static Linux x86_64 downloads.
---

# Linux binary releases

The [release workflow](https://github.com/LuganoPlanB/quietproof/actions/workflows/release.yml)
publishes a static Linux x86_64 CLI after the main-branch `Tests` workflow
succeeds. It builds the exact tested commit. A maintainer can also run the
release workflow manually on `main`; that path runs the test workflow first.
Pull requests build and test the binary without creating tags or releases.

The first release is `v0.1.0`. Later versions are calculated by
[`ietf-tools/semver-action`](https://github.com/ietf-tools/semver-action) from
commits since the latest reachable stable release tag. Conventional `feat:`
commits bump the minor version, `fix:` commits bump the patch version, and
breaking changes bump the major version. Other changes receive a patch release.
Rerunning a release for the same tagged commit reuses that version and replaces
its assets; an existing tag pointing to a different commit is never moved.

Download the archive and matching `.sha256` file from
[GitHub Releases](https://github.com/LuganoPlanB/quietproof/releases):

```sh
sha256sum --check quietproof-v0.1.0-linux-x86_64-musl.tar.gz.sha256
tar -xzf quietproof-v0.1.0-linux-x86_64-musl.tar.gz
./quietproof-v0.1.0-linux-x86_64-musl/bin/quietproof --version
```

Substitute the downloaded version in these filenames. The archive contains the
CLI with native Bitcoin Core RPC enabled, license notices, the README, and
`release.json` recording its version, source and SDK commits, compiler and binary
SHA-256. Bitcoin Core remains a separately operated service.

[`dyne/musl-action`](https://github.com/dyne/musl-action) supplies the x86_64
compiler and static curl/TLS dependencies. The build uses the pinned Longfellow
SDK source and runs the native tests excluding proof-heavy and installed-package
consumer tests. ELF inspection requires x86_64, no interpreter and no shared
library dependencies. The version printed by the binary must match the archive.
These build checks do not replace the separate full proof, live-node or browser
qualification gates described in [operations](./operations).

To reproduce the binary build with the Dyne toolchain installed:

```sh
python3 scripts/build_musl_release.py --sdk-source ../longfellow-zk \
  --work /tmp/quietproof-musl --output output/releases --version 0.1.0
```

The SDK checkout must match `scripts/build-pins.json`. `CC` and `CXX` can select
the compiler paths supplied by the action. CMake's `QUIETPROOF_VERSION` sets the
CLI and installed package version; it does not change protocol or circuit versions.
