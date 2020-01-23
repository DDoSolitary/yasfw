# yasfw

![Build status](https://github.com/DDoSolitary/yasfw/workflows/.github/workflows/build.yml/badge.svg)

Yet Another SSHFS for Windows

# Features

I'm a bit tired when writing this readme, so please download the binaries and find out the amazing features yourself :)

# Screenshot

![](https://i.ibb.co/N683Rrh/yasfw-screenshot.png)

# Install

1. Install [Dokan](https://github.com/dokan-dev/dokany/releases) v1.3 or later.
2. Download from [Releases](https://github.com/DDoSolitary/yasfw/releases) or [dev snapshots](https://dl.bintray.com/ddosolitary/dev-releases/yasfw/).
3. Extract the downloaded archive and run `yasfw --help` to learn about the command line arguments.

# Build

Replace `{ARCH}` in the following instructions with `x86_64` or `i686` depending on the architecture you're building for. Similarly, replace `{DOKAN_ARCH}` with `x64` or `Win32`.

1. Install Rust with the `stable-{ARCH)-pc-windows-gnu` toolchain.
2. Install MSYS2 with the following packages: `mingw-w64-{ARCH)-binutils mingw-w64-{ARCH)-libssh`, and set environment variable `YASFW_MSYS2_DIR` to the installation directory of MSYS2 if it's not installed to the default location (`C:\msys64`).
3. Download the appropriate version of dokan.zip from Dokan's [Releases page](https://github.com/dokan-dev/dokany/releases) and extract the archive, and set environment variable `YASFW_DOKAN_DIR` to `<path-to-extracted-dir>\{DOKAN_ARCH}\Release`.
4. Run `cargo +stable-{ARCH)-pc-windows-gnu build --target {ARCH)-pc-windows-gnu`.
