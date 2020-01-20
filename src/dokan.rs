use std::mem;

use libc::{c_int, c_void, wchar_t};
use widestring::U16CString;
use winapi::shared::{
	minwindef::{FILETIME, MAX_PATH},
	ntdef::{HANDLE, NTSTATUS},
};
use winapi::um::{
	fileapi::BY_HANDLE_FILE_INFORMATION,
	minwinbase::WIN32_FIND_DATAW,
	winnt::{ACCESS_MASK, SECURITY_DESCRIPTOR, SECURITY_INFORMATION},
};

lazy_static! {
	pub static ref DOKAN_VERSION: u16 = env!("YASFW_DOKAN_VERSION").parse().unwrap();
}

bitflags! {
	#[repr(transparent)]
	pub struct DokanOption: u32 {
		const NONE = 0;
		const DEBUG = 1;
		const STDERR = 2;
		const ALT_STREAM = 4;
		const WRITE_PROTECT = 8;
		const NETWORK = 16;
		const REMOVABLE = 32;
		const MOUNT_MANAGER = 64;
		const CURRENT_SESSION = 128;
		const FILELOCK_USER_MODE = 256;
		const ENABLE_NOTIFICATION_API = 512;
		const DISABLE_OPLOCKS = 1024;
		const OPTIMIZE_SINGLE_NAME_SEARCH = 2048;
	}
}

#[repr(i32)]
#[derive(Debug, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum DokanMainResult {
	Success = 0,
	Error = -1,
	DriveLetterError = -2,
	DriverInstallError = -3,
	StartError = -4,
	MountError = -5,
	MountPointError = -6,
	VersionError = -7,
}

#[repr(C)]
#[derive(Debug)]
pub struct DokanOptions {
	pub version: u16,
	pub thread_count: u16,
	pub options: DokanOption,
	pub global_context: u64,
	pub mount_point: *mut wchar_t,
	pub unc_name: *mut wchar_t,
	pub timeout: u32,
	pub allocation_unit_size: u32,
	pub sector_size: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct DokanFileInfo {
	pub context: u64,
	pub dokan_context: u64,
	pub dokan_options: *mut DokanOptions,
	pub process_id: u32,
	pub is_directory: bool,
	pub delete_on_close: bool,
	pub paging_io: bool,
	pub synchronous_io: bool,
	pub no_cache: bool,
	pub write_to_end_of_file: bool,
}

pub type PFillFindData = extern "stdcall" fn(*mut WIN32_FIND_DATAW, *mut DokanFileInfo) -> c_int;
pub type PFillFindStreamData = extern "stdcall" fn(*mut c_void, *mut DokanFileInfo) -> c_int;


#[repr(C)]
pub struct DokanOperations {
	pub zw_create_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		security_context: *mut c_void,
		desired_access: ACCESS_MASK,
		file_attributes: u32,
		share_access: u32,
		create_disposition: u32,
		create_options: u32,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub cleanup: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		dokan_file_info: *mut DokanFileInfo,
	)>,
	pub close_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		dokan_file_info: *mut DokanFileInfo,
	)>,
	pub read_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		buffer: *mut u8,
		buffer_length: u32,
		read_length: *mut u32,
		offset: i64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub write_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		buffer: *const u8,
		number_of_bytes_to_write: u32,
		number_of_bytes_written: *mut u32,
		offset: i64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub flush_file_buffers: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub get_file_information: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		buffer: *mut BY_HANDLE_FILE_INFORMATION,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub find_files: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		fill_find_data: PFillFindData,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub find_files_with_pattern: Option<extern "stdcall" fn(
		path_name: *const wchar_t,
		search_pattern: *const wchar_t,
		fill_find_data: PFillFindData,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub set_file_attributes: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		file_attributes: u32,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub set_file_time: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		creation_time: *const FILETIME,
		last_access_time: *const FILETIME,
		last_write_time: *const FILETIME,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub delete_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub delete_directory: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub move_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		new_file_name: *const wchar_t,
		replace_if_existing: bool,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub set_end_of_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		byte_offset: i64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub set_allocation_size: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		alloc_size: i64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub lock_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		byte_offset: i64,
		length: i64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub unlock_file: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		byte_offset: i64,
		length: i64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub get_disk_free_space: Option<extern "stdcall" fn(
		free_bytes_available: *mut u64,
		total_number_of_bytes: *mut u64,
		total_number_of_free_bytes: *mut u64,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub get_volume_information: Option<extern "stdcall" fn(
		volume_name_buffer: *mut wchar_t,
		volume_name_size: u32,
		volume_serial_number: *mut u32,
		maximum_component_length: *mut u32,
		file_system_flags: *mut u32,
		file_system_name_buffer: *mut wchar_t,
		file_system_name_size: u32,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub mounted: Option<extern "stdcall" fn(dokan_file_info: *mut DokanFileInfo) -> NTSTATUS>,
	pub unmounted: Option<extern "stdcall" fn(dokan_file_info: *mut DokanFileInfo) -> NTSTATUS>,
	pub get_file_security: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		security_information: *mut SECURITY_INFORMATION,
		security_descriptor: *mut SECURITY_DESCRIPTOR,
		buffer_length: u32,
		length_needed: *mut u32,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub set_file_security: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		security_information: *mut SECURITY_INFORMATION,
		security_descriptor: *mut SECURITY_DESCRIPTOR,
		buffer_length: u32,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
	pub find_streams: Option<extern "stdcall" fn(
		file_name: *const wchar_t,
		fill_find_stream_data: PFillFindStreamData,
		dokan_file_info: *mut DokanFileInfo,
	) -> NTSTATUS>,
}

#[repr(C)]
#[allow(dead_code)]
pub struct DokanControl {
	pub fs_type: u32,
	pub mount_point: [wchar_t; MAX_PATH],
	pub unc_name: [wchar_t; 64],
	pub device_name: [wchar_t; 64],
	pub device_object: *mut c_void,
}

#[link(name = "dokan1")]
#[allow(dead_code)]
extern "stdcall" {
	pub fn DokanMain(dokan_options: *const DokanOptions, dokan_operations: *const DokanOperations) -> DokanMainResult;
	pub fn DokanUnmount(drive_letter: wchar_t) -> bool;
	pub fn DokanRemoveMountPoint(mount_point: *const wchar_t) -> bool;
	pub fn DokwnRemoveMountPointEx(mount_point: *const wchar_t, safe: bool) -> bool;
	pub fn DokanIsNameInExpression(expression: *const wchar_t, name: *const wchar_t, ignore_case: bool) -> bool;
	pub fn DokanVersion() -> u32;
	pub fn DokanDriverVersion() -> u32;
	pub fn DokanResetTimeout(timeout: u32, dokan_file_info: DokanFileInfo) -> bool;
	pub fn DokanOpenRequestorToken(dokan_file_info: DokanFileInfo) -> HANDLE;
	pub fn DokanGetMountPointList(list: *mut DokanControl, length: u32, unc_only: bool, nb_read: *mut u32) -> bool;
	pub fn DokanReleaseMountPointList(list: *mut DokanControl);

	pub fn DokanNotifyCreate(file_path: *const wchar_t, is_directory: bool) -> bool;
	pub fn DokanNotifyDelete(file_path: *const wchar_t, is_directory: bool) -> bool;
	pub fn DokanNotifyUpdate(file_path: *const wchar_t) -> bool;
	pub fn DokanNotifyXAttrUpdate(file_path: *const wchar_t) -> bool;
	pub fn DokanNotifyRename(
		old_path: *const wchar_t,
		new_path: *const wchar_t,
		is_directory: bool,
		is_in_same_directory: bool,
	) -> bool;

	pub fn DokanMapKernelToUserCreateFileFlags(
		desired_access: ACCESS_MASK,
		file_attributes: u32,
		create_options: u32,
		create_disposition: u32,
		out_desired_access: *mut ACCESS_MASK,
		out_file_attributes_and_flags: *mut u32,
		out_creation_disposition: *mut u32,
	);
	pub fn DokanNtStatusFromWin32(error: u32) -> NTSTATUS;
}

impl Drop for DokanOptions {
	fn drop(&mut self) {
		unsafe {
			if !self.mount_point.is_null() {
				mem::drop(U16CString::from_raw(self.mount_point))
			}
			if !self.unc_name.is_null() {
				mem::drop(U16CString::from_raw(self.unc_name))
			}
		}
	}
}
