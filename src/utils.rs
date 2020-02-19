use widestring::{U16CStr, U16CString};
use winapi::shared::{ntdef::NTSTATUS, ntstatus::*};

use crate::ssh::SftpErrorCode;

pub fn sftp_error_to_ntstatus(error: SftpErrorCode) -> NTSTATUS {
	use crate::ssh::SftpErrorCode::*;
	match error {
		SftpErrorCode::Ok => STATUS_SUCCESS,
		Eof => STATUS_END_OF_FILE,
		NoSuchFile | NoSuchPath => STATUS_OBJECT_NAME_NOT_FOUND,
		PermissionDenied | CannotDelete => STATUS_ACCESS_DENIED,
		Failure => STATUS_INTERNAL_ERROR,
		BadMessage => STATUS_DEVICE_PROTOCOL_ERROR,
		NoConnection => STATUS_CONNECTION_DISCONNECTED,
		ConnectionLost => STATUS_CONNECTION_RESET,
		OpUnsupported => STATUS_NOT_SUPPORTED,
		InvalidHandle => STATUS_INVALID_HANDLE,
		FileAlreadyExists => STATUS_OBJECT_NAME_COLLISION,
		WriteProtect => STATUS_MEDIA_WRITE_PROTECTED,
		NoMedia => STATUS_NO_MEDIA,
		NoSpaceOnFilesystem => STATUS_DISK_FULL,
		QuotaExceeded => STATUS_QUOTA_EXCEEDED,
		DirNotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
		NotADirectory => STATUS_NOT_A_DIRECTORY,
		InvalidFileName => STATUS_OBJECT_NAME_INVALID,
		LinkLoop => STATUS_IO_REPARSE_TAG_NOT_HANDLED,
		FileIsADirectory => STATUS_FILE_IS_A_DIRECTORY,
		DeletePending => STATUS_DELETE_PENDING,
		FileCorrupt => STATUS_FILE_CORRUPT_ERROR,
		LockConflict | ByteRangeLockConflict => STATUS_FILE_LOCK_CONFLICT,
		ByteRangeLockRefused | NoMatchingByteRangeLock => STATUS_LOCK_NOT_GRANTED,
		UnknownPrinciple | InvalidParameter | OwnerInvalid | GroupInvalid => STATUS_INVALID_PARAMETER
	}
}

pub fn from_nt_path(nt_path: &U16CStr) -> Option<String> {
	nt_path.to_string().ok().map(|s| { s.replace("\\", "/") })
}

fn is_special_char(c: char) -> bool {
	let n = c as u32;
	n >= 1 && n <= 31 || c == '<' || c == '>' || c == ':' || c == '"' || c == '\\' || c == '|' || c == '*' || c == '?'
}

pub fn to_nt_name(linux_path: &str) -> Option<U16CString> {
	if linux_path.chars().any(|c| is_special_char(c)) {
		None
	} else {
		U16CString::from_str(linux_path).ok()
	}
}
