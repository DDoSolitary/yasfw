use std::env;

const DOKAN_VERSION_MAJOR: u32 = 1;
const DOKAN_VERSION_MINOR: u32 = 3;
const DOKAN_VERSION_PATCH: u32 = 1;

fn main() {
	let dokan_dir = env::var("YASFW_DOKAN_DIR").unwrap_or(format!(
		"C:\\Program Files\\Dokan\\Dokan Library-{}.{}.{}\\lib",
		DOKAN_VERSION_MAJOR, DOKAN_VERSION_MINOR, DOKAN_VERSION_PATCH,
	));

	let libssh_dir = env::var("YASFW_LIBSSH_DIR").unwrap_or(format!(
		"{}\\mingw{}\\lib",
		env::var("YASFW_MSYS2_DIR").unwrap_or("C:\\msys64".to_owned()),
		if env::var("TARGET").unwrap().starts_with("x86_64") { "64" } else { "32" },
	));

	println!("cargo:rerun-if-env-changed=YASFW_DOKAN_DIR");
	println!("cargo:rerun-if-env-changed=YASFW_MSYS2_DIR");
	println!("cargo:rerun-if-env-changed=YASFW_LIBSSH_DIR");
	println!("cargo:rustc-link-search=native={}", dokan_dir);
	println!("cargo:rustc-link-search=native={}", libssh_dir);
	println!(
		"cargo:rustc-env=YASFW_DOKAN_VERSION={}{}{}",
		DOKAN_VERSION_MAJOR, DOKAN_VERSION_MINOR, DOKAN_VERSION_PATCH,
	);
}
