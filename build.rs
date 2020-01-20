use std::env;
use std::path::Path;

const DOKAN_VERSION_MAJOR: u32 = 1;
const DOKAN_VERSION_MINOR: u32 = 3;
const DOKAN_VERSION_PATCH: u32 = 1;

fn main() {
	let mut dokan_dir = env::var("YASFW_DOKAN_DIR")
		.map(|s| Path::new(&s).to_owned())
		.unwrap_or(Path::new("C:\\Program Files\\Dokan").to_owned());
	dokan_dir.push(Path::new(&format!(
		"Dokan Library-{}.{}.{}\\lib",
		DOKAN_VERSION_MAJOR, DOKAN_VERSION_MINOR, DOKAN_VERSION_PATCH,
	)));

	let libssh_dir = env::var("YASFW_LIBSSH_DIR")
		.unwrap_or(String::from("C:\\msys64\\mingw64\\lib"));

	println!("cargo:rustc-link-search=native={}", dokan_dir.to_str().unwrap());
	println!("cargo:rustc-link-search=native={}", libssh_dir);
	println!(
		"cargo:rustc-env=YASFW_DOKAN_VERSION={}{}{}",
		DOKAN_VERSION_MAJOR, DOKAN_VERSION_MINOR, DOKAN_VERSION_PATCH,
	);
}
