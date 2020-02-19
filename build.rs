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

fn main() {
	let msys2_dir = env::var("YASFW_MSYS2_DIR").unwrap_or("C:\\msys64".to_owned());
	let mingw_dir = format!(
		"{}\\mingw{}", msys2_dir,
		if env::var("TARGET").unwrap().starts_with("x86_64") { "64" } else { "32" },
	);
	let libssh_dir = env::var("YASFW_LIBSSH_DIR").unwrap_or(format!("{}\\lib", mingw_dir));
	let toolchain_dir = env::var("YASFW_TOOLCHAIN_DIR").unwrap_or(format!("{}\\bin", mingw_dir));

	let version = get_version();
	let win_version = get_win_version(&version);

	let mut res = WindowsResource::new();
	res.set_language(winnt::MAKELANGID(winnt::LANG_ENGLISH, winnt::SUBLANG_ENGLISH_US));
	res.set_version_info(VersionInfo::FILEVERSION, win_version);
	res.set_version_info(VersionInfo::PRODUCTVERSION, win_version);
	res.set("FileVersion", &version);
	res.set("ProductVersion", &version);
	res.set("OriginalFilename", "yasfw.exe");
	res.set("LegalCopyright", "Copyright (c) 2020 DDoSolitary");
	res.set("CompanyName", "DDoSolitary");

	let old_path = env::var("PATH").unwrap();
	env::set_var("PATH", format!("{};{}", toolchain_dir, old_path));
	res.compile().unwrap();
	env::set_var("PATH", &old_path);

	println!("cargo:rerun-if-changed=.git/logs/HEAD");
	println!("cargo:rerun-if-changed=.git/refs/tags");
	println!("cargo:rerun-if-env-changed=YASFW_MSYS2_DIR");
	println!("cargo:rerun-if-env-changed=YASFW_LIBSSH_DIR");
	println!("cargo:rustc-link-search=native={}", libssh_dir);
	println!("cargo:rustc-env=YASFW_VERSION=v{}", version);
}
