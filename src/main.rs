#[macro_use]
extern crate bitflags;
extern crate clap;
extern crate ctrlc;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate lru;
extern crate rpassword;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
extern crate widestring;
extern crate winapi;

use std::{error::Error, mem, ptr, rc::Rc, slice, sync::Mutex};

use clap::{App, Arg};
use libc::{c_void, wchar_t};
use lru::LruCache;
use slog::{Drain, Level, Logger};
use slog_async::{Async, OverflowStrategy};
use slog_term::{CompactFormat, TermDecorator};
use widestring::U16CString;
use winapi::shared::{
	minwindef::{FILETIME, MAX_PATH},
	ntdef::NTSTATUS,
	ntstatus::{*, STATUS_INVALID_PARAMETER},
};
use winapi::um::{
	fileapi::{BY_HANDLE_FILE_INFORMATION, CREATE_ALWAYS, CREATE_NEW, OPEN_ALWAYS, OPEN_EXISTING, TRUNCATE_EXISTING},
	minwinbase::WIN32_FIND_DATAW,
	winnt::*,
};

use dokan::*;
use ssh::*;

mod dokan;
mod ssh;
mod utils;

struct GlobalContext {
	sftp_session: SftpSession,
	logger: Logger,
	file_type_cache: Mutex<LruCache<String, SftpFileType>>,
	file_size_cache: Mutex<LruCache<String, u64>>,
	directory_cache: Mutex<LruCache<String, Vec<String>>>,
	ignore_case: bool,
}

struct FileContext<'a> {
	file: SftpFile<'a>,
	path: String,
}

impl GlobalContext {
	fn new(sftp_session: SftpSession, logger: Logger, ignore_case: bool) -> GlobalContext {
		GlobalContext {
			sftp_session,
			logger,
			file_type_cache: Mutex::new(LruCache::new(1024)),
			file_size_cache: Mutex::new(LruCache::new(1024)),
			directory_cache: Mutex::new(LruCache::new(1024)),
			ignore_case,
		}
	}

	fn get_file_type(&self, logger: &Logger, path: &String, file: &SftpFile, no_cache: bool) -> SshResult<SftpFileType> {
		let mut cache = self.file_type_cache.lock().unwrap();
		let cache_result = if no_cache { None } else {
			cache.get(path).map(|file_type| {
				trace!(logger, "file type cache hit");
				Ok(file_type.clone())
			})
		};
		if let Some(file_type) = cache_result { file_type } else {
			let file_type = file.attributes()?.file_type();
			cache.put(path.to_owned(), file_type);
			Ok(file_type)
		}
	}

	fn get_file_size(&self, logger: &Logger, path: &String, file: &SftpFile, no_cache: bool) -> SshResult<Option<u64>> {
		let mut cache = self.file_size_cache.lock().unwrap();
		let cache_result = if no_cache { None } else {
			cache.get(path).map(|size| {
				trace!(logger, "file size cache hit");
				Ok(Some(size.clone()))
			})
		};
		if let Some(size) = cache_result { size } else {
			let size = file.attributes()?.size();
			if let Some(size) = size {
				cache.put(path.to_owned(), size);
			}
			Ok(size)
		}
	}

	fn get_directory_content(&self, logger: &Logger, path: &String, sftp_session: &SftpSession, no_cache: bool) -> SshResult<Vec<String>> {
		let mut cache = self.directory_cache.lock().unwrap();
		let cache_result = if no_cache { None } else {
			cache.get(path).map(|list| {
				trace!(logger, "directory content cache hit");
				Ok(list.to_owned())
			})
		};
		if let Some(list) = cache_result { list } else {
			let list = sftp_session.open_directory(path)?
				.collect::<Result<Vec<_>, _>>()?.iter()
				.filter_map(|attr| attr.name().map(|name| name.to_owned()))
				.filter(|name| name != "." && name != "..")
				.collect::<Vec<_>>();
			cache.put(path.to_owned(), list.to_owned());
			Ok(list)
		}
	}

	fn update_size_if_in_cache<F>(&self, logger: &Logger, path: &String, f: F)
		where F: FnOnce(u64) -> u64 {
		if let Some(size) = self.file_size_cache.lock().unwrap().peek_mut(path) {
			*size = f(*size);
			trace!(logger, "file size cache updated"; "new_size" => *size);
		}
	}

	fn invalidate_cache(&self, logger: &Logger, path: &String) {
		if self.file_type_cache.lock().unwrap().pop(path).is_some() {
			trace!(logger, "file type cache invalidated");
		}
		if self.file_size_cache.lock().unwrap().pop(path).is_some() {
			trace!(logger, "file size cache invalidated");
		}
		let mut directory_cache = self.directory_cache.lock().unwrap();
		if directory_cache.pop(path).is_some() {
			trace!(logger, "directory listing cache invalidated");
		}
		if let Some(index) = path.rfind('/') {
			if directory_cache.pop(&path[..index].to_owned()).is_some() {
				trace!(logger, "directory listing cache invalidated");
			}
		}
	}
}

fn get_global_context<'a, 'b>(dokan_file_info: &'a DokanFileInfo) -> &'b GlobalContext {
	unsafe { &*((&*dokan_file_info.dokan_options).global_context as *const GlobalContext) }
}

fn call_fn<F>(logger: &Logger, f: F) -> NTSTATUS where F: FnOnce() -> SshResult<NTSTATUS> {
	debug!(logger, "operation started");
	let status = match f() {
		Ok(status) => {
			status
		}
		Err(e) => {
			error!(logger, "error occurred when communicating with the server"; "error" => format!("{:?}", e));
			if let Some(code) = e.sftp_error_code() {
				let sftp_status = utils::sftp_error_to_ntstatus(code);
				if sftp_status == STATUS_SUCCESS {
					warn!(logger, "error occurred but SFTP error code is OK");
					STATUS_INTERNAL_ERROR
				} else {
					sftp_status
				}
			} else {
				warn!(logger, "no SFTP error code provided");
				STATUS_INTERNAL_ERROR
			}
		}
	};
	debug!(logger, "operation completed"; "NTSTATUS" => format!("0x{:08x}", status));
	status
}

fn run<F>(op_name: &str, info: *mut DokanFileInfo, f: F) -> NTSTATUS
	where F: FnOnce(&Logger, &mut DokanFileInfo, &GlobalContext) -> SshResult<NTSTATUS> {
	unsafe {
		let info = &mut *info;
		let ctx = get_global_context(info);
		let logger = ctx.logger.new(o!(
			"op" => op_name.to_owned(),
			"handle_id" => info.dokan_context,
			"process_id" => info.process_id,
		));
		call_fn(&logger, || { f(&logger, info, ctx) })
	}
}

fn run_with_file<F>(op_name: &str, info: *mut DokanFileInfo, f: F) -> NTSTATUS
	where F: FnOnce(&Logger, &mut DokanFileInfo, &GlobalContext, &FileContext) -> SshResult<NTSTATUS> {
	unsafe {
		let info = &mut *info;
		let global_context = get_global_context(info);
		let file_context = &mut *(info.context as *mut FileContext);
		let logger = global_context.logger.new(o!(
			"op" => op_name.to_owned(),
			"handle_id" => info.dokan_context,
			"process_id" => info.process_id,
			"path" => file_context.path.clone(),
		));
		call_fn(&logger, || { f(&logger, info, global_context, file_context) })
	}
}

fn dispose_file_context(logger: &Logger, info: &mut DokanFileInfo) {
	if info.context != 0 {
		trace!(logger, "cleaning up file context");
		unsafe {
			let ctx = Box::from_raw(info.context as *mut FileContext);
			mem::drop(ctx);
			info.context = 0;
		}
	}
}

// TODO: Make ignore_case configurable.
fn match_path(logger: &Logger, ctx: &GlobalContext, prefix: &str, path: &[&str], ignore_case: bool, no_cache: bool) -> SshResult<Option<String>> {
	trace!(logger, "matching path"; "prefix" => prefix, "path" => format!("{:?}", path), "ignore_case" => ignore_case);
	if path.is_empty() {
		return Ok(Some(prefix.to_owned()));
	}
	let dir_path = if prefix.is_empty() { String::from("/") } else { prefix.to_owned() };
	let files = ctx.get_directory_content(logger, &dir_path, &ctx.sftp_session, no_cache)?;
	let result = if files.iter().any(|name| name == path[0]) {
		trace!(logger, "exact match found");
		match_path(logger, ctx, &format!("{}/{}", prefix, path[0]), &path[1..], ignore_case, no_cache)
	} else {
		if ignore_case {
			if let Some(actual_name) = files.iter().find(|name| name.eq_ignore_ascii_case(path[0])) {
				trace!(logger, "case insensitive match found"; "name" => actual_name);
				match_path(logger, ctx, &format!("{}/{}", prefix, actual_name), &path[1..], ignore_case, no_cache)
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	};
	if let Ok(None) = result {
		trace!(logger, "matching failed");
	}
	result
}

extern "stdcall" fn zw_create_file(
	file_name: *const wchar_t,
	_security_context: *mut c_void,
	desired_access: ACCESS_MASK,
	file_attributes: u32,
	_share_access: u32,
	create_disposition: u32,
	create_options: u32,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run("ZwCreateFile", dokan_file_info, |logger, info, ctx| {
		let linux_path = if let Some(path) = unsafe { utils::from_nt_path_ptr(file_name) } { path } else {
			return Ok(STATUS_OBJECT_NAME_INVALID);
		};
		let mut user_desired_access = 0u32;
		let mut user_file_flags = 0u32;
		let mut user_disposition = 0u32;
		unsafe {
			DokanMapKernelToUserCreateFileFlags(
				desired_access, file_attributes, create_options, create_disposition,
				&mut user_desired_access, &mut user_file_flags, &mut user_disposition,
			);
		}
		debug!(
			logger, "arguments preprocessed";
			"desired_access" => format!("0x{:08x}", user_desired_access),
			"flags" => format!("0x{:08x}", user_file_flags),
			"disposition" => user_disposition,
		);
		let mut linux_access = AccessType::empty();
		if (user_desired_access & (GENERIC_READ | GENERIC_EXECUTE)) > 0 {
			linux_access = AccessType::O_RDONLY;
		}
		if (user_desired_access & GENERIC_WRITE) > 0 {
			linux_access = AccessType::O_WRONLY;
		}
		if linux_access.contains(AccessType::O_RDONLY | AccessType::O_WRONLY) {
			linux_access = AccessType::O_RDWR;
		}
		if (user_desired_access & GENERIC_ALL) > 0 {
			linux_access = AccessType::O_RDWR;
		}
		if info.is_directory {
			// SFTP server will return error when opening a directory with write access.
			linux_access = AccessType::O_RDONLY;
		}
		let split_path = linux_path.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>();
		let last_offset = split_path.len().max(1) - 1;
		let dir_match_result = match_path(logger, ctx, "", &split_path[..last_offset], ctx.ignore_case, info.no_cache)?;
		let actual_dir_path = if let Some(path) = dir_match_result { path } else {
			debug!(logger, "parent directory not found");
			return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
		};
		let match_result = match_path(logger, ctx, &actual_dir_path, &split_path[last_offset..], ctx.ignore_case, info.no_cache)?;
		match user_disposition {
			CREATE_NEW => if match_result.is_some() {
				debug!(logger, "file already exists");
				return Ok(STATUS_OBJECT_NAME_COLLISION);
			} else {
				linux_access |= AccessType::O_CREAT;
			},
			CREATE_ALWAYS | OPEN_ALWAYS => {
				linux_access |= AccessType::O_CREAT;
			}
			OPEN_EXISTING | TRUNCATE_EXISTING => if match_result.is_none() {
				debug!(logger, "file not found");
				return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
			},
			_ => {
				error!(logger, "invalid disposition"; "disposition" => user_disposition);
				return Ok(STATUS_INVALID_PARAMETER);
			}
		}
		let actual_path = match_result.as_ref()
			.map(|s| if s.is_empty() { String::from("/") } else { s.to_owned() })
			.unwrap_or_else(|| format!("{}/{}", actual_dir_path, split_path[last_offset]));
		let logger = logger.new(o!("path" => actual_path.clone()));
		debug!(logger, "path canonicalized");
		if match_result.is_none() {
			ctx.invalidate_cache(&logger, &actual_path);
		}
		if info.is_directory && linux_access.contains(AccessType::O_CREAT) {
			if match_result.is_none() {
				debug!(logger, "creating directory");
				ctx.sftp_session.create_directory(
					&actual_path,
					Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO,
				)?;
				linux_access.remove(AccessType::O_CREAT);
			} else {
				return Ok(STATUS_OBJECT_NAME_COLLISION);
			}
		}
		trace!(logger, "opening file"; "flags" => format!("{:?}", linux_access));
		let file = ctx.sftp_session.open_file(
			&actual_path, linux_access,
			// umask will be applied on the server.
			Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP | Mode::S_IROTH | Mode::S_IWOTH,
		)?;
		let file_type = ctx.get_file_type(&logger, &actual_path, &file, info.no_cache)?;
		let logger = logger.new(o!("file_type" => format!("{:?}", file_type)));
		trace!(logger, "file type retrieved");
		match file_type {
			SftpFileType::Regular => if info.is_directory {
				debug!(logger, "directory requested but file found");
				return Ok(STATUS_NOT_A_DIRECTORY);
			} else if user_disposition == CREATE_ALWAYS || user_disposition == TRUNCATE_EXISTING {
				debug!(logger, "truncating file");
				ctx.sftp_session.set_file_size(&actual_path, 0)?;
				ctx.update_size_if_in_cache(&logger, &actual_path, |_| 0);
			},
			SftpFileType::Directory => {
				debug!(logger, "directory found, updating file info");
				info.is_directory = true
			}
			_ => {
				warn!(logger, "unsupported file");
				return Ok(STATUS_NOT_SUPPORTED);
			}
		}
		dispose_file_context(&logger, info);
		info.context = Box::into_raw(Box::new(FileContext { file, path: actual_path })) as u64;
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn cleanup(
	_file_name: *const wchar_t,
	_dokan_file_info: *mut DokanFileInfo,
) {}

extern "stdcall" fn close_file(
	_file_name: *const wchar_t,
	dokan_file_info: *mut DokanFileInfo,
) {
	let mut tmp_logger = None;
	run_with_file("CloseFile", dokan_file_info, |logger, info, gctx, fctx| {
		tmp_logger = Some(logger.clone());
		if info.delete_on_close {
			gctx.invalidate_cache(logger, &fctx.path);
			if info.is_directory {
				debug!(logger, "deleting directory");
				gctx.sftp_session.delete_directory(&fctx.path)?;
			} else {
				debug!(logger, "deleting file");
				gctx.sftp_session.delete_file(&fctx.path)?;
			}
		}
		Ok(STATUS_SUCCESS)
	});
	unsafe { dispose_file_context(tmp_logger.as_ref().unwrap(), &mut *dokan_file_info) };
}

extern "stdcall" fn read_file(
	_file_name: *const wchar_t,
	buffer: *mut u8,
	buffer_length: u32,
	read_length: *mut u32,
	offset: i64,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("ReadFile", dokan_file_info, |logger, _, _, ctx| {
		unsafe {
			debug!(logger, "reading file"; "offset" => offset, "count" => buffer_length);
			let buffer = slice::from_raw_parts_mut(buffer, buffer_length as usize);
			*read_length = 0;
			while *read_length < buffer_length {
				let bytes_read = ctx.file.read(
					offset as u64 + *read_length as u64,
					&mut buffer[*read_length as usize..],
				)?;
				trace!(logger, "data received"; "bytes_read" => bytes_read);
				if bytes_read == 0 { break; }
				*read_length += bytes_read as u32;
			}
			debug!(logger, "reading completed"; "bytes_read" => *read_length);
		}
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn write_file(
	_file_name: *const wchar_t,
	buffer: *const u8,
	number_of_bytes_to_write: u32,
	number_of_bytes_written: *mut u32,
	offset: i64,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("WriteFile", dokan_file_info, |logger, info, gctx, fctx| {
		unsafe {
			let offset = if info.write_to_end_of_file {
				trace!(logger, "WriteToEndOfFile is set, getting file size");
				if let Some(size) = gctx.get_file_size(logger, &fctx.path, &fctx.file, info.no_cache)? { size } else {
					error!(logger, "server didn't provide file size");
					return Ok(STATUS_INTERNAL_ERROR);
				}
			} else {
				offset as u64
			};
			debug!(logger, "writing file"; "offset" => offset, "count" => number_of_bytes_to_write);
			let buffer = slice::from_raw_parts(buffer, number_of_bytes_to_write as usize);
			*number_of_bytes_written = 0;
			while *number_of_bytes_written < number_of_bytes_to_write {
				let buffer_begin = *number_of_bytes_written as usize;
				// Strangely writing more than 262199 bytes at once will cause errors (according to
				// my experiments) so let's choose a smaller value.
				// Maybe this should be moved to SftpFile::write.
				let buffer_end = buffer.len().min(buffer_begin + 65536);
				let bytes_written = fctx.file.write(
					offset + *number_of_bytes_written as u64,
					&buffer[buffer_begin..buffer_end],
				)?;
				trace!(logger, "data sent"; "bytes_written" => bytes_written);
				*number_of_bytes_written += bytes_written as u32;
			}
			debug!(logger, "writing completed"; "bytes_written" => *number_of_bytes_written);
			gctx.update_size_if_in_cache(logger, &fctx.path, |size| size.max(offset));
		}
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn flush_file_buffers(
	_file_name: *const wchar_t,
	_dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	STATUS_SUCCESS
}

extern "stdcall" fn get_file_information(
	_file_name: *const wchar_t,
	buffer: *mut BY_HANDLE_FILE_INFORMATION,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("GetFileInformation", dokan_file_info, |logger, info, gctx, fctx| {
		let file_info = unsafe { &mut *buffer };
		let attr = fctx.file.attributes()?;
		let file_type = attr.file_type();
		let logger = logger.new(o!("file_type" => format!("{:?}", file_type)));
		file_info.dwFileAttributes = match file_type {
			SftpFileType::Regular => FILE_ATTRIBUTE_NORMAL,
			SftpFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
			_ => {
				error!(logger, "unsupported file");
				return Ok(STATUS_NOT_SUPPORTED);
			}
		};
		file_info.ftCreationTime = utils::unix_to_filetime(attr.create_time().unwrap_or(0), attr.create_time_nsec().unwrap_or(0));
		file_info.ftLastAccessTime = utils::unix_to_filetime(attr.atime().unwrap_or(0), attr.atime_nsec().unwrap_or(0));
		file_info.ftLastWriteTime = utils::unix_to_filetime(attr.mtime().unwrap_or(0), attr.mtime_nsec().unwrap_or(0));
		file_info.dwVolumeSerialNumber = 0;
		let size = attr.size().unwrap_or(0);
		file_info.nFileSizeHigh = (size >> 32) as u32;
		file_info.nFileSizeLow = size as u32;
		// It's an ugly hack because SFTP doesn't provide a way to fetch these information.
		file_info.nNumberOfLinks = 1;
		let id = info.context;
		file_info.nFileIndexHigh = (id >> 32) as u32;
		file_info.nFileIndexLow = id as u32;
		debug!(logger, "file info retrieved"; "size" => size, "id" => id);
		gctx.file_type_cache.lock().unwrap().put(fctx.path.clone(), file_type);
		gctx.update_size_if_in_cache(&logger, &fctx.path, |_| size);
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn find_files(
	_path_name: *const wchar_t,
	fill_find_data: PFillFindData,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("FindFiles", dokan_file_info, |logger, info, gctx, fctx| {
		let dir = gctx.sftp_session.open_directory(&fctx.path)?;
		let mut name_list = vec!();
		for attr in dir {
			let attr = attr?;
			let name = if let Some(name) = attr.name() { name } else {
				error!(logger, "server didn't provide file name");
				continue;
			};
			if name == "." || name == ".." {
				// Dokan will add them automatically.
				continue;
			}
			name_list.push(name.to_owned());
			let mut file_type = attr.file_type();
			let logger = logger.new(o!("name" => name.to_owned(), "file_type" => format!("{:?}", file_type)));
			trace!(logger, "new file found");
			let path = format!("{}/{}", fctx.path, name);
			if file_type == SftpFileType::Symlink {
				let resolve_result = gctx.sftp_session.open_file(&path, AccessType::O_RDONLY, Mode::empty()).and_then(|file| {
					file_type = gctx.get_file_type(&logger, &path, &file, info.no_cache)?;
					Ok(())
				});
				if let Err(e) = resolve_result {
					warn!(logger, "failed to resolve symlink"; "error" => format!("{:?}", e));
					continue;
				} else {
					trace!(logger, "target file type retrieved"; "target_type" => format!("{:?}", file_type));
				}
			}
			let is_dir = match file_type {
				SftpFileType::Regular => false,
				SftpFileType::Directory => true,
				_ => {
					warn!(logger, "unsupported file");
					continue;
				}
			};
			let size = if is_dir { 0 } else { attr.size().unwrap_or(0) };
			let logger = logger.new(o!("size" => size));
			let mut data = WIN32_FIND_DATAW {
				dwFileAttributes: if is_dir {
					FILE_ATTRIBUTE_DIRECTORY
				} else {
					FILE_ATTRIBUTE_NORMAL
				},
				ftCreationTime: utils::unix_to_filetime(attr.create_time().unwrap_or(0), attr.create_time_nsec().unwrap_or(0)),
				ftLastAccessTime: utils::unix_to_filetime(attr.atime().unwrap_or(0), attr.atime_nsec().unwrap_or(0)),
				ftLastWriteTime: utils::unix_to_filetime(attr.mtime().unwrap_or(0), attr.mtime_nsec().unwrap_or(0)),
				nFileSizeHigh: (size >> 32) as u32,
				nFileSizeLow: size as u32,
				dwReserved0: 0,
				dwReserved1: 0,
				cFileName: [0; MAX_PATH],
				cAlternateFileName: [0; 14],
			};
			let nt_name = if let Some(name) = utils::to_nt_name(name) { name } else {
				warn!(logger, "unsupported file name");
				continue;
			};
			if nt_name.len() > MAX_PATH {
				warn!(logger, "file name too long");
				continue;
			}
			(&mut data.cFileName[0..nt_name.len()]).copy_from_slice(nt_name.as_slice());
			trace!(logger, "filling find data");
			fill_find_data(&mut data, dokan_file_info);
			gctx.file_type_cache.lock().unwrap().put(path.clone(), file_type);
			gctx.update_size_if_in_cache(&logger, &path, |_| size);
		}
		gctx.directory_cache.lock().unwrap().put(fctx.path.clone(), name_list);
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn set_file_time(
	_file_name: *const wchar_t,
	creation_time: *const FILETIME,
	last_access_time: *const FILETIME,
	last_write_time: *const FILETIME,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("SetFileTime", dokan_file_info, |logger, _, gctx, fctx| {
		unsafe {
			let (atime, atime_nsec) = utils::filetime_to_unix(&*last_access_time);
			let (create_time, create_time_nsec) = utils::filetime_to_unix(&*creation_time);
			let (mtime, mtime_nsec) = utils::filetime_to_unix(&*last_write_time);
			trace!(
				logger, "setting file time";
				"atime" => atime as f64 + atime_nsec as f64 / 1e9,
				"createtime" => create_time as f64 + create_time_nsec as f64 / 1e9,
				"mtime" => mtime as f64 + mtime_nsec as f64 / 1e9,
			);
			gctx.sftp_session.set_file_time(
				&fctx.path,
				atime, atime_nsec,
				create_time, create_time_nsec,
				mtime, mtime_nsec,
			)?;
		}
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn delete_file(
	_file_name: *const wchar_t,
	_dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	STATUS_SUCCESS
}

extern "stdcall" fn delete_directory(
	_file_name: *const wchar_t,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("DeleteDirectory", dokan_file_info, |logger, info, gctx, fctx| {
		let list = gctx.get_directory_content(logger, &fctx.path, &gctx.sftp_session, info.no_cache)?;
		if list.is_empty() {
			Ok(STATUS_SUCCESS)
		} else {
			debug!(logger, "directory not empty");
			Ok(STATUS_DIRECTORY_NOT_EMPTY)
		}
	})
}

extern "stdcall" fn move_file(
	_file_name: *const wchar_t,
	new_file_name: *const wchar_t,
	replace_if_existing: bool,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("MoveFile", dokan_file_info, |logger, info, gctx, fctx| {
		let new_linux_path = if let Some(path) = unsafe { utils::from_nt_path_ptr(new_file_name) } { path } else {
			warn!(logger, "invalid new path");
			return Ok(STATUS_OBJECT_NAME_INVALID);
		};
		let split_new_path = new_linux_path.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>();
		let last_offset = split_new_path.len().max(1) - 1;
		let dir_match_result = match_path(logger, gctx, "", &split_new_path[..last_offset], gctx.ignore_case, info.no_cache)?;
		let new_actual_path = if let Some(path) = dir_match_result {
			format!("{}/{}", path, split_new_path.last().unwrap_or(&""))
		} else {
			debug!(logger, "parent directory not found");
			return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
		};
		let logger = logger.new(o!("new_path" => new_actual_path.clone()));
		if let Ok(file) = gctx.sftp_session.open_file(&new_actual_path, AccessType::O_RDONLY, Mode::empty()) {
			let is_dir = gctx.get_file_type(&logger, &new_actual_path, &file, info.no_cache)? == SftpFileType::Directory;
			debug!(
				logger, "new name already exists";
				"replace_if_existing" => replace_if_existing,
				"is_dir" => info.is_directory,
				"new_path_is_dir" => is_dir,
			);
			mem::drop(file);
			if replace_if_existing {
				if !info.is_directory && !is_dir {
					debug!(logger, "deleting existing file");
					gctx.sftp_session.delete_file(&new_actual_path)?;
				} else {
					return Ok(STATUS_ACCESS_DENIED);
				}
			} else {
				return Ok(STATUS_OBJECT_NAME_COLLISION);
			}
		}
		gctx.invalidate_cache(&logger, &fctx.path);
		gctx.invalidate_cache(&logger, &new_actual_path);
		debug!(logger, "moving file");
		gctx.sftp_session.rename(&fctx.path, &new_actual_path)?;
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn set_end_of_file(
	_file_name: *const wchar_t,
	byte_offset: i64,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("SetEndOfFile", dokan_file_info, |logger, _, gctx, fctx| {
		debug!(logger, "setting file size"; "size" => byte_offset);
		gctx.sftp_session.set_file_size(&fctx.path, byte_offset as u64)?;
		gctx.update_size_if_in_cache(logger, &fctx.path, |_| byte_offset as u64);
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn set_allocation_size(
	_file_name: *const wchar_t,
	alloc_size: i64,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run_with_file("SetAllocationSize", dokan_file_info, |logger, _, gctx, fctx| {
		debug!(logger, "setting file size"; "size" => alloc_size);
		gctx.sftp_session.set_file_size(&fctx.path, alloc_size as u64)?;
		gctx.update_size_if_in_cache(logger, &fctx.path, |_| alloc_size as u64);
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn get_disk_free_space(
	free_bytes_available: *mut u64,
	total_number_of_bytes: *mut u64,
	total_number_of_free_bytes: *mut u64,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run("GetDiskFreeSpace", dokan_file_info, |logger, _, ctx| {
		let stat = ctx.sftp_session.stat_vfs(".")?;
		unsafe {
			if !free_bytes_available.is_null() {
				let val = stat.blocks_available() * stat.fragment_size();
				trace!(logger, "setting available byte count"; "value" => val);
				*free_bytes_available = val;
			}
			if !total_number_of_bytes.is_null() {
				let val = stat.blocks() * stat.fragment_size();
				trace!(logger, "setting total byte count"; "value" => val);
				*total_number_of_bytes = val;
			}
			if !total_number_of_free_bytes.is_null() {
				let val = stat.blocks_free() * stat.fragment_size();
				trace!(logger, "setting free byte count"; "value" => val);
				*total_number_of_free_bytes = val;
			}
		}
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn get_volume_information(
	volume_name_buffer: *mut wchar_t,
	volume_name_size: u32,
	volume_serial_number: *mut u32,
	maximum_component_length: *mut u32,
	file_system_flags: *mut u32,
	file_system_name_buffer: *mut wchar_t,
	file_system_name_size: u32,
	dokan_file_info: *mut DokanFileInfo,
) -> NTSTATUS {
	run("GetVolumeInformation", dokan_file_info, |logger, _, ctx| {
		let volume_name = U16CString::from_str("Test").unwrap();
		// Custom names (such as SSHFS) don't play well with UAC.
		let fs_name = U16CString::from_str("NTFS").unwrap();
		if volume_name.len() > volume_name_size as usize || fs_name.len() > file_system_name_size as usize {
			return Ok(STATUS_BUFFER_TOO_SMALL);
		}
		unsafe {
			ptr::copy(volume_name.as_ptr(), volume_name_buffer, volume_name.len());
			ptr::copy(fs_name.as_ptr(), file_system_name_buffer, fs_name.len());
			if volume_serial_number != ptr::null_mut() {
				*volume_serial_number = 0;
			}
			*file_system_flags = FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_SEQUENTIAL_WRITE_ONCE | FILE_UNICODE_ON_DISK
		}
		let stat = ctx.sftp_session.stat_vfs(".")?;
		trace!(logger, "setting max name length"; "value" => stat.name_max());
		unsafe { *maximum_component_length = stat.name_max() as u32 }
		Ok(STATUS_SUCCESS)
	})
}

extern "stdcall" fn mounted(dokan_file_info: *mut DokanFileInfo) -> NTSTATUS {
	unsafe {
		let logger = &get_global_context(&*dokan_file_info).logger;
		info!(logger, "mounted");
	}
	STATUS_SUCCESS
}

extern "stdcall" fn unmounted(dokan_file_info: *mut DokanFileInfo) -> NTSTATUS {
	unsafe {
		let options = &mut *(&*dokan_file_info).dokan_options;
		let ctx = Box::from_raw(options.global_context as *mut GlobalContext);
		info!(ctx.logger, "unmounted");
		mem::drop(ctx);
		options.global_context = 0;
	}
	STATUS_SUCCESS
}

extern fn get_passphrase(prompt: &str) -> Option<String> {
	rpassword::prompt_password_stdout(prompt).ok()
}

fn main() {
	let matches = App::new(env!("CARGO_PKG_NAME"))
		.version(env!("YASFW_VERSION"))
		.author(env!("CARGO_PKG_AUTHORS"))
		.about(env!("CARGO_PKG_DESCRIPTION"))
		.arg(Arg::with_name("server").short("s").long("server").takes_value(true).value_name("SERVER_ADDR").required(true).help("SFTP server address."))
		.arg(Arg::with_name("port").short("p").long("port").takes_value(true).value_name("PORT").default_value("22").help("Server port."))
		.arg(Arg::with_name("user").short("u").long("user").takes_value(true).value_name("USER").required(true).help("Username."))
		.arg(Arg::with_name("key").short("k").long("key").takes_value(true).value_name("KEY_FILE").help("Private key file."))
		.arg(Arg::with_name("mount_point").short("m").long("mount-point").takes_value(true).value_name("MOUNT_POINT").required(true).help("Drive letter to mount to."))
		.arg(Arg::with_name("thread_count").short("t").long("threads").takes_value(true).value_name("THREAD_COUNT").default_value("0").help("Thread count. Use \"0\" to let Dokan choose it automatically."))
		.arg(Arg::with_name("ignore_case").short("i").long("ignore-case").help("Enable support for case-insensitive paths."))
		.arg(Arg::with_name("dokan_debug").short("d").long("dokan-debug").help("Enable Dokan's debug output."))
		.arg(Arg::with_name("removable").short("r").long("removable").help("Mount as a removable drive."))
		.arg(Arg::with_name("log_level").short("l").long("log-level").takes_value(true).default_value("Info").possible_values(&["Error", "Warning", "Info", "Debug", "Trace"]).help("Logging level."))
		.get_matches();

	let log_level = match matches.value_of("log_level").unwrap().to_ascii_lowercase().as_str() {
		"error" => Level::Error,
		"warning" => Level::Warning,
		"info" => Level::Info,
		"debug" => Level::Debug,
		"trace" => Level::Trace,
		_ => panic!("unexpected logging level"),
	};
	let decorator = TermDecorator::new().stdout().build();
	let drain = CompactFormat::new(decorator).build().ignore_res();
	let drain = Async::new(drain).overflow_strategy(OverflowStrategy::Block).build().ignore_res();
	let drain = drain.filter_level(log_level).ignore_res();
	let logger = Logger::root(drain, o!());

	let result = (|| -> Result<(), Box<dyn Error>> {
		let port = matches.value_of("port").unwrap().parse()?;
		let thread_count = matches.value_of("thread_count").unwrap().parse()?;
		let mount_point = matches.value_of("mount_point").unwrap();
		if mount_point.len() > 1 || !mount_point.is_ascii() {
			error!(logger, "invalid mount point");
			return Ok(());
		}
		let mount_point = mount_point.chars().next().unwrap();

		unsafe { info!(logger, "initializing"; "dokan_version" => DokanVersion(), "dokan_driver_version" => DokanDriverVersion()); }
		let mut session = SshSession::new().expect("failed to initialize the SSH session");
		session.set_host(matches.value_of("server").unwrap())?;
		session.set_port(port)?;
		session.set_user(matches.value_of("user").unwrap())?;
		session.connect()?;
		if let Some(hash) = session.server_public_key()?.hash(ssh::SshPublicKeyHashType::SHA256) {
			info!(logger, "connected established"; "server_public_key" => hash.hex_string());
		} else {
			error!(logger, "failed to retrieve server public key");
			return Ok(());
		}

		debug!(logger, "trying none authentication");
		let mut auth_result = session.auth_none();
		match auth_result {
			SshAuthResult::Error => return Err(Box::new(session.last_error())),
			SshAuthResult::Denied => debug!(logger, "none authentication failed"),
			SshAuthResult::Partial => debug!(logger, "partially authenticated using none"),
			_ => (),
		}
		let auth_list = session.auth_method_list();
		let auth_list_str = format!("{:?}", auth_list);
		debug!(logger, "server authentication methods retrieved"; "server_auth_methods" => &auth_list_str);
		if auth_result != SshAuthResult::Success {
			if let Some(key_file) = matches.value_of("key") {
				if auth_list.contains(SshAuthMethod::PUBLICKEY) {
					debug!(logger, "trying public key authentication");
					if let Some(key) = SshKey::from_private_key_file(key_file, get_passphrase) {
						auth_result = session.auth_public_key(&key);
					} else {
						error!(logger, "failed to load the key file");
						return Ok(());
					}
					match auth_result {
						SshAuthResult::Error => return Err(Box::new(session.last_error())),
						SshAuthResult::Denied => warn!(logger, "public key authentication failed"),
						SshAuthResult::Partial => info!(logger, "partially authenticated using private key"),
						_ => (),
					}
				} else {
					warn!(logger, "private key file provided but server doesn't allow public key authentication");
				}
			}
		}
		if auth_result != SshAuthResult::Success {
			if auth_list.contains(SshAuthMethod::PASSWORD) {
				debug!(logger, "trying password authentication");
				let password = rpassword::prompt_password_stdout("Password: ")?;
				auth_result = session.auth_password(&password);
			} else {
				debug!(logger, "password authentication is now allowed by server")
			}
		}
		let auth_result_str = format!("{:?}", auth_result);
		match auth_result {
			SshAuthResult::Error => return Err(Box::new(session.last_error())),
			SshAuthResult::Denied | SshAuthResult::Partial => {
				error!(logger, "authentication failed"; "auth_result" => auth_result_str, "server_auth_methods" => &auth_list_str);
				return Ok(());
			}
			SshAuthResult::Success => info!(logger, "authentication succeeded"),
			_ => {
				error!(logger, "unexpected authentication result"; "auth_result" => auth_result_str);
				return Ok(());
			}
		}

		let sftp_session = SftpSession::new(Rc::new(session), logger.clone())?;
		let mut option_flags = DokanOption::MOUNT_MANAGER | DokanOption::OPTIMIZE_SINGLE_NAME_SEARCH;
		if matches.is_present("dokan_debug") {
			option_flags.insert(DokanOption::DEBUG | DokanOption::STDERR);
		}
		if matches.is_present("removable") {
			option_flags.insert(DokanOption::REMOVABLE);
		}
		let ctx = GlobalContext::new(sftp_session, logger.clone(), matches.is_present("ignore_case"));
		let options = DokanOptions {
			version: *DOKAN_VERSION,
			thread_count,
			options: option_flags,
			global_context: Box::into_raw(Box::new(ctx)) as u64,
			mount_point: U16CString::from_str(format!("{}:\\", mount_point))?.into_raw(),
			unc_name: ptr::null_mut(),
			timeout: 0,
			allocation_unit_size: 0,
			sector_size: 0,
		};
		let operations = DokanOperations {
			zw_create_file: Some(zw_create_file),
			cleanup: Some(cleanup),
			close_file: Some(close_file),
			read_file: Some(read_file),
			write_file: Some(write_file),
			flush_file_buffers: Some(flush_file_buffers),
			get_file_information: Some(get_file_information),
			find_files: Some(find_files),
			find_files_with_pattern: None,
			set_file_attributes: None,
			set_file_time: Some(set_file_time),
			delete_file: Some(delete_file),
			delete_directory: Some(delete_directory),
			move_file: Some(move_file),
			set_end_of_file: Some(set_end_of_file),
			set_allocation_size: Some(set_allocation_size),
			lock_file: None,
			unlock_file: None,
			get_disk_free_space: Some(get_disk_free_space),
			get_volume_information: Some(get_volume_information),
			mounted: Some(mounted),
			unmounted: Some(unmounted),
			get_file_security: None,
			set_file_security: None,
			find_streams: None,
		};
		unsafe {
			let cloned_logger = logger.clone();
			ctrlc::set_handler(move || {
				if !DokanUnmount(mount_point as u16) {
					error!(cloned_logger, "failed to unmount");
					std::process::exit(1);
				}
			})?;
			let result = DokanMain(&options, &operations);
			info!(logger, "exiting"; "dokan_result" => format!("{:?}", result));
		}
		Ok(())
	})();
	if let Err(e) = result {
		error!(logger, "error occurred"; "error" => format!("{:?}", e));
	}
}
