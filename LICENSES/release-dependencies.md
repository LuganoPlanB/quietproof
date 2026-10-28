# Static Linux release dependencies

The musl release archive includes QuietProof's GPLv3 license (`COPYING`), the
pinned Longfellow SDK's Apache 2.0 license, and the notices below for libraries
and compiler runtimes linked from the Dyne x86_64 toolchain.

| Notice | Source |
| --- | --- |
| `curl-COPYING.txt` | [curl 8.15.0 COPYING](https://github.com/curl/curl/blob/curl-8_15_0/COPYING) |
| `LibreSSL-COPYING.txt` | `libressl-4.1.0/COPYING` in [Dyne's source mirror](https://files.dyne.org/musl/sources/libressl-4.1.0.tar.gz) |
| `zlib-ng-LICENSE.txt` | [zlib-ng 2.2.4 LICENSE.md](https://github.com/zlib-ng/zlib-ng/blob/2.2.4/LICENSE.md) |
| `musl-COPYRIGHT.txt` | [musl 1.2.5 COPYRIGHT](https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT?h=v1.2.5) |
| `GCC-RUNTIME-EXCEPTION.txt` | [GCC 15.1.0 runtime exception](https://github.com/gcc-mirror/gcc/blob/releases/gcc-15.1.0/COPYING.RUNTIME), used with GPLv3 in `COPYING` |

These files retain the upstream notices. The toolchain's corresponding sources
are available from [dyne/musl](https://github.com/dyne/musl) and its
[source mirror](https://files.dyne.org/musl/sources/). The archive's
`release.json` identifies the compiler and the exact QuietProof/Longfellow source
commits. Review these notices when updating the toolchain dependencies.
