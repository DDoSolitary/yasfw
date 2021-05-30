extern crate cmake;
extern crate pkg_config;
extern crate vcpkg;
extern crate winapi;
extern crate winres;

use std::{env, process::Command};

use winapi::um::winnt;
use winres::{VersionInfo, WindowsResource};

fn get_version() -> String {
	let describe_result = Command::new("git").args(&["describe", "--tags"]).output()
		.map_err(|e| e.to_string())
		.and_then(|output| {
			if output.status.success() {
				Ok(String::from_utf8(output.stdout).unwrap().trim()[1..].to_owned())
			} else {
				Err(format!("git describe command exited with {:?}", output.status.code()))
			}
		});
	match describe_result {
		Ok(version) => version,
		Err(msg) => {
			println!("cargo:warning={}", msg);
			println!("cargo:warning=git describe failed, falling back to crate version.");
			env::var("CARGO_PKG_VERSION").unwrap()
		}
	}
}

fn get_win_version(version: &str) -> u64 {
	let components = version[..version.find('-').unwrap_or(version.len())].split('.').collect::<Vec<_>>();
	components[0].parse::<u64>().unwrap() << 48 | components[1].parse::<u64>().unwrap() << 32 | components[2].parse::<u64>().unwrap() << 16
}

fn compile_res() {
	let version = get_version();
	let win_version = get_win_version(&version);
	WindowsResource::new()
		.set_language(winnt::MAKELANGID(winnt::LANG_ENGLISH, winnt::SUBLANG_ENGLISH_US))
		.set_version_info(VersionInfo::FILEVERSION, win_version)
		.set_version_info(VersionInfo::PRODUCTVERSION, win_version)
		.set("FileVersion", &version)
		.set("ProductVersion", &version)
		.set("OriginalFilename", &format!("{}.exe", env::var("CARGO_PKG_NAME").unwrap()))
		.set("LegalCopyright", "Copyright (c) 2020 DDoSolitary")
		.set("CompanyName", "DDoSolitary")
		.compile().unwrap();
	println!("cargo:rerun-if-changed=.git/logs/HEAD");
	println!("cargo:rerun-if-changed=.git/refs/tags");
	println!("cargo:rustc-env=YASFW_VERSION=v{}", version);
}

fn find_deps() {
	let is_static = env::var("LIBSSH_STATIC").unwrap_or("0".to_owned()) != "0";
	println!("cargo:rerun-if-env-changed=LIBSSH_STATIC");
	match env::var("CARGO_CFG_TARGET_ENV").unwrap().as_ref() {
		"gnu" => {
			env::set_var("PKG_CONFIG_ALL_STATIC", if is_static { "1" } else { "0" });
			let ssh_out = cmake::Config::new("libssh-pageant")
				.profile("Release")
				.static_crt(is_static)
				.define("BUILD_SHARED_LIBS", if is_static { "OFF" } else { "ON" })
				.define("WITH_EXAMPLES", "OFF")
				.build();
			println!("cargo:rustc-link-search=native={}/lib", ssh_out.display());
			if is_static {
				let mut pkg_cfg = pkg_config::Config::new();
				pkg_cfg.env_metadata(true);
				pkg_cfg.probe("openssl").unwrap();
				pkg_cfg.probe("zlib").unwrap();
				println!("cargo:rustc-cfg=libssh_static");
				println!("cargo:rustc-link-lib=static=ssh");
			} else {
				println!("cargo:rustc-link-lib=dylib=ssh");
			}
		}
		"msvc" => {
			let vcpkg_toolchain = format!("{}/scripts/buildsystems/vcpkg.cmake", env::var("VCPKG_ROOT").unwrap());
			let vcpkg_arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_ref() {
				"x86_64" => "x64",
				"x86" => "x86",
				"arm" => "arm",
				"aarch64" => "arm64",
				arch => panic!("Unsupported architecture: {}", arch),
			};
			let vcpkg_triplet = format!("{}-windows{}", vcpkg_arch, if is_static { "-static" } else { "" });
			let ssh_out = cmake::Config::new("libssh-pageant")
				.profile("Release")
				.static_crt(is_static)
				.define("CMAKE_TOOLCHAIN_FILE", vcpkg_toolchain)
				.define("VCPKG_TARGET_TRIPLET", vcpkg_triplet)
				.define("BUILD_SHARED_LIBS", if is_static { "OFF" } else { "ON" })
				.define("WITH_MBEDTLS", "ON")
				.define("WITH_EXAMPLES", "OFF")
				.build();
			println!("cargo:rustc-link-search=native={}/lib", ssh_out.display());
			if is_static {
				vcpkg::find_package("mbedtls").unwrap();
				vcpkg::find_package("zlib").unwrap();
				println!("cargo:rustc-cfg=libssh_static");
				println!("cargo:rustc-link-lib=static=ssh");
			} else {
				println!("cargo:rustc-link-lib=dylib=ssh");
			}
		}
		e => panic!("Unsupported target environment: {}", e),
	};
}

fn main() {
	let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
	if &target_family != "windows" {
		panic!("Unsupported target family: {}", target_family);
	}
	compile_res();
	find_deps();
}
