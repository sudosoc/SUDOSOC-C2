This page summarizes implant payload format compatibility by target OS/architecture (`GOOS/GOARCH`).

## Common Platforms

| Target OS/Arch  | Executable | Shared Library | Shellcode | Service |
| --------------- | ---------- | -------------- | --------- | ------- |
| `windows/386`   | ✅         | ✅             | ✅        | ✅      |
| `windows/amd64` | ✅         | ✅             | ✅        | ✅      |
| `windows/arm64` | ⚠️         | ⚠️             | ❌        | ⚠️      |
| `linux/386`     | ✅         | ✅             | ❌        | N/A     |
| `linux/amd64`   | ✅         | ✅             | ✅        | N/A     |
| `linux/arm64`   | ✅         | ✅             | ✅        | N/A     |
| `darwin/amd64`  | ✅         | ✅             | ❌        | N/A     |
| `darwin/arm64`  | ✅         | ✅             | ✅        | N/A     |

### Important Notes

- `✅` = first-class support in Sliver's built-in target matrix.
- `⚠️` = generic/experimental target (not first-class; may fail depending on toolchain/target).
- `❌` = not currently supported for that payload format.
- `Service` is a Windows-only format.
- `Shellcode` is currently supported for `windows/{386,amd64}`, `linux/{amd64,arm64}`, and `darwin/arm64`.
- `Shellcode` and `Shared Library` for MacOS may require a [cross-compiler](/docs?name=Cross-compiling+Implants) or an [external builder](/docs?name=External+Builders) depending on your platform.
- On macOS hosts, targeting `linux/386` for shared library/shellcode builds is currently not reliable.

Use `generate info` in the SUDOSOC-C2 console to see what your current server can build with its configured toolchains.

## All GOOS/GOARCH Targets

The table below covers all `GOOS/GOARCH` entries from `go tool dist list` (Go 1.24+), including common platforms:

| Target GOOS/GOARCH | Common Platform | Executable | Shared Library | Shellcode | Service |
| ------------------ | --------------- | ---------- | -------------- | --------- | ------- |
| `aix/ppc64` | No | ⚠️ | ❌ | ❌ | N/A |
| `android/386` | No | ⚠️ | ❌ | ❌ | N/A |
| `android/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `android/arm` | No | ⚠️ | ❌ | ❌ | N/A |
| `android/arm64` | No | ⚠️ | ❌ | ❌ | N/A |
| `darwin/amd64` | Yes | ✅ | ✅ | ❌ | N/A |
| `darwin/arm64` | Yes | ✅ | ✅ | ✅ | N/A |
| `dragonfly/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `freebsd/386` | No | ⚠️ | ❌ | ❌ | N/A |
| `freebsd/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `freebsd/arm` | No | ⚠️ | ❌ | ❌ | N/A |
| `freebsd/arm64` | No | ⚠️ | ❌ | ❌ | N/A |
| `freebsd/riscv64` | No | ⚠️ | ❌ | ❌ | N/A |
| `illumos/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `ios/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `ios/arm64` | No | ⚠️ | ❌ | ❌ | N/A |
| `js/wasm` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/386` | Yes | ✅ | ✅ | ❌ | N/A |
| `linux/amd64` | Yes | ✅ | ✅ | ✅ | N/A |
| `linux/arm` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/arm64` | Yes | ✅ | ✅ | ✅ | N/A |
| `linux/loong64` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/mips` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/mips64` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/mips64le` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/mipsle` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/ppc64` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/ppc64le` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/riscv64` | No | ⚠️ | ❌ | ❌ | N/A |
| `linux/s390x` | No | ⚠️ | ❌ | ❌ | N/A |
| `netbsd/386` | No | ⚠️ | ❌ | ❌ | N/A |
| `netbsd/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `netbsd/arm` | No | ⚠️ | ❌ | ❌ | N/A |
| `netbsd/arm64` | No | ⚠️ | ❌ | ❌ | N/A |
| `openbsd/386` | No | ⚠️ | ❌ | ❌ | N/A |
| `openbsd/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `openbsd/arm` | No | ⚠️ | ❌ | ❌ | N/A |
| `openbsd/arm64` | No | ⚠️ | ❌ | ❌ | N/A |
| `openbsd/ppc64` | No | ⚠️ | ❌ | ❌ | N/A |
| `openbsd/riscv64` | No | ⚠️ | ❌ | ❌ | N/A |
| `plan9/386` | No | ⚠️ | ❌ | ❌ | N/A |
| `plan9/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `plan9/arm` | No | ⚠️ | ❌ | ❌ | N/A |
| `solaris/amd64` | No | ⚠️ | ❌ | ❌ | N/A |
| `wasip1/wasm` | No | ⚠️ | ❌ | ❌ | N/A |
| `windows/386` | Yes | ✅ | ✅ | ✅ | ✅ |
| `windows/amd64` | Yes | ✅ | ✅ | ✅ | ✅ |
| `windows/arm64` | Yes | ⚠️ | ⚠️ | ❌ | ⚠️ |
