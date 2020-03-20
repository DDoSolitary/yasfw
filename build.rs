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
				Ok(String::from_utf8(output.stdout).unwrap()[1..].to_owned())
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
	match env::var("CARGO_CFG_TARGET_ENV").unwrap().as_ref() {
		"gnu" => {
			let mut cfg = pkg_config::Config::new();
			cfg.env_metadata(true);
			cfg.probe("libssh").unwrap();
			if env::var("PKG_CONFIG_ALL_STATIC").is_ok() || env::var("LIBSSH_STATIC").is_ok() {
				cfg.probe("openssl").unwrap();
				cfg.probe("zlib").unwrap();
				println!("cargo:rustc-link-lib=shell32");
				println!("cargo:rustc-cfg=libssh_static");
			}
		}
		"msvc" => {
			let lib = vcpkg::find_package("libssh").unwrap();
			if lib.is_static {
				println!("cargo:rustc-link-lib=static=crypt32");
				println!("cargo:rustc-link-lib=static=shell32");
				println!("cargo:rustc-link-lib=static=user32");
				println!("cargo:rustc-cfg=libssh_static");
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
