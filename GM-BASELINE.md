# libSRTP GM baseline

This directory is the libSRTP baseline used by the Electron `v43.3.0`
DTLS-SRTP GM work.

- Electron baseline: `v43.3.0`
- Source location: `src/third_party/libsrtp`
- Upstream repository: `https://github.com/cisco/libsrtp`
- Baseline commit: `cd5d177bf1fde755ddb4c7f0d9ff7693f8b49e5e`
- `LIBSRTP_VERSION`: `24b3bf8f19b6f5ab4cd2bcceb4f4064efca`
- Working branch: `gm-libsrtp-v43.3.0`
- Baseline tag: `v43.3.0-libsrtp-gm0`

The source is the Chromium/Electron vendored snapshot. It retains the
Chromium local modifications, including removal of unused non-OpenSSL cipher
implementations and renaming `VERSION` to `LIBSRTP_VERSION`.

No SM4-GCM implementation or `SRTP_SM4_GCM` profile is included in this
baseline tag. The first follow-up commit adds the BoringSSL-backed SM4-GCM
cipher adapter and the PoC profile policy, but it is not yet accepted as an
interoperability-complete implementation until the shared JVB vectors and
Electron build pass.
