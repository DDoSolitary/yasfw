#[macro_use]
extern crate bitflags;
extern crate clap;
extern crate ctrlc;
extern crate dokan;
extern crate libc;
extern crate lru;
extern crate rpassword;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
extern crate widestring;
extern crate winapi;

mod auth;
mod ssh;
mod utils;

use std::cell::Cell;
use std::error::Error;
use std::mem;
use std::process;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{App, Arg};
use dokan::*;
use lru::LruCache;
use slog::{Drain, Level, Logger};
use slog_async::{Async, OverflowStrategy};
use slog_term::{CompactFormat, TermDecorator};
use widestring::{U16CStr, U16CString};
use winapi::shared::{ntdef::NTSTATUS, ntstatus::{*, STATUS_INVALID_PARAMETER}};
use winapi::um::{fileapi, winnt::*};

use ssh::*;

struct FileContext<'a> {
	file: SftpFile<'a>,
	path: String,
}

enum SshfsError {
	NtStatus(NTSTATUS),
	SshError(SshError),
}

impl From<SshError> for SshfsError {
	fn from(e: SshError) -> SshfsError {
		SshfsError::SshError(e)
	}
}

struct SshfsHandler {
	sftp_session: SftpSession,
	logger: Logger,
	server_name: U16CString,
	ignore_case: bool,
	file_type_cache: Mutex<LruCache<String, SftpFileType>>,
	file_size_cache: Mutex<LruCache<String, u64>>,
	directory_cache: Mutex<LruCache<String, Vec<String>>>,
}

impl SshfsHandler {
	fn new(sftp_session: SftpSession, logger: Logger, server_name: U16CString, ignore_case: bool) -> SshfsHandler {
		SshfsHandler {
			sftp_session,
			logger,
			server_name,
			ignore_case,
			file_type_cache: Mutex::new(LruCache::new(1024)),
			file_size_cache: Mutex::new(LruCache::new(1024)),
			directory_cache: Mutex::new(LruCache::new(1024)),
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

	fn get_directory_content(&self, logger: &Logger, path: &String, no_cache: bool) -> SshResult<Vec<String>> {
		let mut cache = self.directory_cache.lock().unwrap();
		let cache_result = if no_cache { None } else {
			cache.get(path).map(|list| {
				trace!(logger, "directory content cache hit");
				Ok(list.to_owned())
			})
		};
		if let Some(list) = cache_result { list } else {
			let list = self.sftp_session.open_directory(path)?
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


	fn match_path(&self, logger: &Logger, prefix: &str, path: &[&str], no_cache: bool) -> SshResult<Option<String>> {
		trace!(logger, "matching path"; "prefix" => prefix, "path" => format!("{:?}", path), "ignore_case" => self.ignore_case);
		if path.is_empty() {
			return Ok(Some(prefix.to_owned()));
		}
		let dir_path = if prefix.is_empty() { String::from("/") } else { prefix.to_owned() };
		let files = self.get_directory_content(logger, &dir_path, no_cache)?;
		let result = if files.iter().any(|name| name == path[0]) {
			trace!(logger, "exact match found");
			self.match_path(logger, &format!("{}/{}", prefix, path[0]), &path[1..], no_cache)
		} else {
			if self.ignore_case {
				if let Some(actual_name) = files.iter().find(|name| name.eq_ignore_ascii_case(path[0])) {
					trace!(logger, "case insensitive match found"; "name" => actual_name);
					self.match_path(logger, &format!("{}/{}", prefix, actual_name), &path[1..], no_cache)
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

	fn run<F, T>(&self, op_name: &str, info: &OperationInfo<Self>, context: Option<&FileContext>, f: F) -> Result<T, OperationError>
		where F: FnOnce(&Logger) -> Result<T, SshfsError> {
		let mut logger = self.logger.new(o!(
				"op" => op_name.to_owned(),
				"process_id" => info.pid(),
			));
		if let Some(context) = context {
			logger = logger.new(o!(
					"object_id" => context as *const FileContext as usize,
					"path" => context.path.clone(),
				));
		}
		//call_fn(&logger, || { f(&logger, info, global_context, file_context) })
		debug!(logger, "operation started");
		match f(&logger) {
			Ok(ret) => {
				debug!(logger, "operation completed successfully");
				Ok(ret)
			}
			Err(SshfsError::NtStatus(e)) => {
				debug!(logger, "operation completed with an error"; "NTSTATUS" => format!("0x{:08x}", e));
				Err(OperationError::NtStatus(e))
			}
			Err(SshfsError::SshError(e)) => {
				error!(logger, "error occurred when communicating with the server"; "error" => format!("{:?}", e));
				if let Some(code) = e.sftp_error_code() {
					let sftp_status = utils::sftp_error_to_ntstatus(code);
					if sftp_status == STATUS_SUCCESS {
						warn!(logger, "error occurred but SFTP error code is OK");
						Err(OperationError::NtStatus(STATUS_INTERNAL_ERROR))
					} else {
						Err(OperationError::NtStatus(sftp_status))
					}
				} else {
					warn!(logger, "no SFTP error code provided");
					Err(OperationError::NtStatus(STATUS_INTERNAL_ERROR))
				}
			}
		}
	}
}

impl<'a, 'b: 'a> FileSystemHandler<'a, 'b> for SshfsHandler {
	type Context = FileContext<'a>;

	fn create_file(
		&'b self,
		file_name: &U16CStr,
		_security_context: dokan::PDOKAN_IO_SECURITY_CONTEXT,
		desired_access: ACCESS_MASK,
		file_attributes: u32,
		_share_access: u32,
		create_disposition: u32,
		create_options: u32,
		info: &mut OperationInfo<Self>,
	) -> Result<CreateFileInfo<Self::Context>, OperationError> {
		self.run("CreateFile", info, None, |logger| {
			let linux_path = if let Some(path) = utils::from_nt_path(file_name) { path } else {
				return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_INVALID));
			};
			let user_flags = dokan::map_kernel_to_user_create_file_flags(
				desired_access,
				file_attributes,
				create_options,
				create_disposition,
			);
			debug!(
				logger, "arguments preprocessed";
				"desired_access" => format!("0x{:08x}", user_flags.desired_access),
				"flags" => format!("0x{:08x}", user_flags.flags_and_attributes),
				"disposition" => user_flags.creation_disposition,
			);
			let mut linux_access = AccessType::empty();
			if (user_flags.desired_access & (GENERIC_READ | GENERIC_EXECUTE)) > 0 {
				linux_access = AccessType::O_RDONLY;
			}
			if (user_flags.desired_access & GENERIC_WRITE) > 0 {
				linux_access = AccessType::O_WRONLY;
			}
			if linux_access.contains(AccessType::O_RDONLY | AccessType::O_WRONLY) {
				linux_access = AccessType::O_RDWR;
			}
			if (user_flags.desired_access & GENERIC_ALL) > 0 {
				linux_access = AccessType::O_RDWR;
			}
			if info.is_dir() {
				// SFTP server will return error when opening a directory with write access.
				linux_access = AccessType::O_RDONLY;
			}
			let split_path = linux_path.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>();
			let last_offset = split_path.len().max(1) - 1;
			let dir_match_result = self.match_path(logger, "", &split_path[..last_offset], info.no_cache())?;
			let actual_dir_path = if let Some(path) = dir_match_result { path } else {
				debug!(logger, "parent directory not found");
				return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_NOT_FOUND));
			};
			let match_result = self.match_path(logger, &actual_dir_path, &split_path[last_offset..], info.no_cache())?;
			let creating_new = match user_flags.creation_disposition {
				fileapi::CREATE_NEW => if match_result.is_none() { true } else {
					debug!(logger, "file already exists");
					return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_COLLISION));
				},
				fileapi::CREATE_ALWAYS | fileapi::OPEN_ALWAYS => {
					match_result.is_none()
				}
				fileapi::OPEN_EXISTING | fileapi::TRUNCATE_EXISTING => if match_result.is_some() { false } else {
					debug!(logger, "file not found");
					return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_NOT_FOUND));
				},
				_ => {
					error!(logger, "invalid disposition"; "disposition" => user_flags.creation_disposition);
					return Err(SshfsError::NtStatus(STATUS_INVALID_PARAMETER));
				}
			};
			let actual_path = match_result.as_ref()
				.map(|s| if s.is_empty() { String::from("/") } else { s.to_owned() })
				.unwrap_or_else(|| format!("{}/{}", actual_dir_path, split_path[last_offset]));
			let logger = logger.new(o!("path" => actual_path.clone()));
			debug!(logger, "path canonicalized");
			if match_result.is_none() {
				self.invalidate_cache(&logger, &actual_path);
			}
			if creating_new {
				if info.is_dir() {
					debug!(logger, "creating directory");
					self.sftp_session.create_directory(
						&actual_path,
						Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO,
					)?;
				} else {
					linux_access |= AccessType::O_CREAT;
				}
			}
			trace!(logger, "opening file"; "flags" => format!("{:?}", linux_access));
			let file = self.sftp_session.open_file(
				&actual_path, linux_access,
				// umask will be applied on the server.
				Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP | Mode::S_IROTH | Mode::S_IWOTH,
			)?;
			let file_type = self.get_file_type(&logger, &actual_path, &file, info.no_cache())?;
			let logger = logger.new(o!("file_type" => format!("{:?}", file_type)));
			trace!(logger, "file type retrieved");
			match file_type {
				SftpFileType::Regular => if info.is_dir() {
					debug!(logger, "directory requested but file found");
					return Err(SshfsError::NtStatus(STATUS_NOT_A_DIRECTORY));
				} else {
					if let fileapi::CREATE_ALWAYS | fileapi::TRUNCATE_EXISTING = user_flags.creation_disposition {
						debug!(logger, "truncating file");
						self.sftp_session.set_file_size(&actual_path, 0)?;
						self.update_size_if_in_cache(&logger, &actual_path, |_| 0);
					}
				},
				SftpFileType::Directory => (),
				_ => {
					warn!(logger, "unsupported file");
					return Err(SshfsError::NtStatus(STATUS_NOT_SUPPORTED));
				}
			}
			Ok(CreateFileInfo {
				context: FileContext { file, path: actual_path },
				is_dir: file_type == SftpFileType::Directory,
				new_file_created: creating_new,
			})
		})
	}

	fn cleanup(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) {
		self.run("Cleanup", info, Some(context), |logger| {
			if info.delete_on_close() {
				self.invalidate_cache(logger, &context.path);
				if info.is_dir() {
					debug!(logger, "deleting directory");
					self.sftp_session.delete_directory(&context.path)?;
				} else {
					debug!(logger, "deleting file");
					self.sftp_session.delete_file(&context.path)?;
				}
			}
			Ok(())
		}).unwrap();
	}

	fn close_file(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) {
		// Call self.run so that the event gets logged.
		self.run("CloseFile", info, Some(context), |_logger| {
			Ok(())
		}).unwrap();
	}

	fn read_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		buffer: &mut [u8],
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		self.run("ReadFile", info, Some(context), |logger| {
			debug!(logger, "reading file"; "offset" => offset, "count" => buffer.len());
			let mut total_bytes_read = 0;
			while (total_bytes_read as usize) < buffer.len() {
				let bytes_read = context.file.read(
					offset as u64 + total_bytes_read as u64,
					&mut buffer[total_bytes_read as usize..],
				)?;
				trace!(logger, "data received"; "bytes_read" => bytes_read);
				if bytes_read == 0 { break; }
				total_bytes_read += bytes_read as u32;
			}
			debug!(logger, "reading completed"; "bytes_read" => total_bytes_read);
			Ok(total_bytes_read)
		})
	}

	fn write_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		buffer: &[u8],
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		self.run("WriteFile", info, Some(context), |logger| {
			let offset = if info.write_to_eof() {
				trace!(logger, "WriteToEndOfFile is set, getting file size");
				if let Some(size) = self.get_file_size(logger, &context.path, &context.file, info.no_cache())? { size } else {
					error!(logger, "server didn't provide file size");
					return Err(SshfsError::NtStatus(STATUS_INTERNAL_ERROR));
				}
			} else {
				offset as u64
			};
			debug!(logger, "writing file"; "offset" => offset, "count" => buffer.len());
			let mut total_bytes_written = 0;
			while (total_bytes_written as usize) < buffer.len() {
				let buffer_begin = total_bytes_written as usize;
				// Strangely writing more than 262199 bytes at once will cause errors (according to
				// my experiments) so let's choose a smaller value.
				// Maybe this should be moved to SftpFile::write.
				let buffer_end = buffer.len().min(buffer_begin + 65536);
				let bytes_written = context.file.write(
					offset + total_bytes_written as u64,
					&buffer[buffer_begin..buffer_end],
				)?;
				trace!(logger, "data sent"; "bytes_written" => bytes_written);
				total_bytes_written += bytes_written as u32;
			}
			debug!(logger, "writing completed"; "bytes_written" => total_bytes_written);
			self.update_size_if_in_cache(logger, &context.path, |size| size.max(offset));
			Ok(total_bytes_written)
		})
	}

	fn get_file_information(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<FileInfo, OperationError> {
		self.run("GetFileInformation", info, Some(context), |logger| {
			let attr = context.file.attributes()?;
			let file_type = attr.file_type();
			let logger = logger.new(o!("file_type" => format!("{:?}", file_type)));
			let file_info = FileInfo {
				attributes: match file_type {
					SftpFileType::Regular => FILE_ATTRIBUTE_NORMAL,
					SftpFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
					_ => {
						error!(logger, "unsupported file");
						return Err(SshfsError::NtStatus(STATUS_NOT_SUPPORTED));
					}
				},
				creation_time: UNIX_EPOCH
					+ Duration::from_secs(attr.create_time().unwrap_or(0))
					+ Duration::from_nanos(attr.create_time_nsec().unwrap_or(0) as u64),
				last_access_time: UNIX_EPOCH
					+ Duration::from_secs(attr.atime().unwrap_or(0))
					+ Duration::from_nanos(attr.atime_nsec().unwrap_or(0) as u64),
				last_write_time: UNIX_EPOCH
					+ Duration::from_secs(attr.mtime().unwrap_or(0))
					+ Duration::from_nanos(attr.mtime_nsec().unwrap_or(0) as u64),
				file_size: attr.size().unwrap_or(0),
				// It's an ugly hack because SFTP doesn't provide a way to fetch these information.
				number_of_links: 1,
				file_index: context as *const FileContext as u64,
			};
			debug!(logger, "file info retrieved"; "size" => file_info.file_size, "id" => file_info.file_index);
			self.file_type_cache.lock().unwrap().put(context.path.clone(), file_type);
			self.update_size_if_in_cache(&logger, &context.path, |_| file_info.file_size);
			Ok(file_info)
		})
	}


	fn find_files(
		&'b self,
		_file_name: &U16CStr,
		mut fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		self.run("FindFiles", info, Some(context), |logger| {
			let dir = self.sftp_session.open_directory(&context.path)?;
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
				let path = format!("{}/{}", context.path, name);
				if file_type == SftpFileType::Symlink {
					let resolve_result = self.sftp_session.open_file(&path, AccessType::O_RDONLY, Mode::empty()).and_then(|file| {
						file_type = self.get_file_type(&logger, &path, &file, info.no_cache())?;
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
				let data = FindData {
					attributes: if is_dir {
						FILE_ATTRIBUTE_DIRECTORY
					} else {
						FILE_ATTRIBUTE_NORMAL
					},
					creation_time: UNIX_EPOCH
						+ Duration::from_secs(attr.create_time().unwrap_or(0))
						+ Duration::from_nanos((attr.create_time_nsec().unwrap_or(0) % 1_000_000_000) as u64),
					last_access_time: UNIX_EPOCH
						+ Duration::from_secs(attr.atime().unwrap_or(0))
						+ Duration::from_nanos((attr.atime_nsec().unwrap_or(0) % 1_000_000_000) as u64),
					last_write_time: UNIX_EPOCH
						+ Duration::from_secs(attr.mtime().unwrap_or(0))
						+ Duration::from_nanos((attr.mtime_nsec().unwrap_or(0) % 1_000_000_000) as u64),
					file_size: size,
					file_name: if let Some(name) = utils::to_nt_name(name) { name } else {
						warn!(logger, "unsupported file name");
						continue;
					},
				};
				let logger = logger.new(o!("size" => data.file_size));
				trace!(logger, "filling find data");
				match fill_find_data(&data) {
					Ok(_) => (),
					Err(e) => {
						warn!(logger, "error occurred when filling find data"; "error" => format!("{:?}", e));
						continue;
					}
				}
				self.file_type_cache.lock().unwrap().put(path.clone(), file_type);
				self.update_size_if_in_cache(&logger, &path, |_| data.file_size);
			}
			self.directory_cache.lock().unwrap().put(context.path.clone(), name_list);
			Ok(())
		})
	}

	fn set_file_time(
		&'b self,
		_file_name: &U16CStr,
		creation_time: SystemTime,
		last_access_time: SystemTime,
		last_write_time: SystemTime,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		self.run("SetFileTime", info, Some(context), |logger| {
			let atime = last_access_time.duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
			let create_time = creation_time.duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
			let mtime = last_write_time.duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
			trace!(
				logger, "setting file time";
				"atime" => atime.as_secs_f64(),
				"createtime" => create_time.as_secs_f64(),
				"mtime" => mtime.as_secs_f64(),
			);
			self.sftp_session.set_file_time(
				&context.path,
				atime.as_secs(), (atime.as_nanos() % 1_000_000_000) as u32,
				create_time.as_secs(), (create_time.as_nanos() % 1_000_000_000) as u32,
				mtime.as_secs(), (mtime.as_nanos() % 1_000_000_000) as u32,
			)?;
			Ok(())
		})
	}

	fn delete_file(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		// Call self.run so that the event gets logged.
		self.run("DeleteFile", info, Some(context), |_logger| {
			Ok(())
		})
	}

	fn delete_directory(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		self.run("DeleteDirectory", info, Some(context), |logger| {
			let list = self.get_directory_content(logger, &context.path, info.no_cache())?;
			if list.is_empty() {
				Ok(())
			} else {
				debug!(logger, "directory not empty");
				Err(SshfsError::NtStatus(STATUS_DIRECTORY_NOT_EMPTY))
			}
		})
	}

	fn move_file(
		&'b self,
		_file_name: &U16CStr,
		new_file_name: &U16CStr,
		replace_if_existing: bool,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		self.run("MoveFile", info, Some(context), |logger| {
			let new_linux_path = if let Some(path) = utils::from_nt_path(new_file_name) { path } else {
				warn!(logger, "invalid new path");
				return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_INVALID));
			};
			let split_new_path = new_linux_path.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>();
			let last_offset = split_new_path.len().max(1) - 1;
			let dir_match_result = self.match_path(logger, "", &split_new_path[..last_offset], info.no_cache())?;
			let new_actual_path = if let Some(path) = dir_match_result {
				format!("{}/{}", path, split_new_path.last().unwrap_or(&""))
			} else {
				debug!(logger, "parent directory not found");
				return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_NOT_FOUND));
			};
			let logger = logger.new(o!("new_path" => new_actual_path.clone()));
			if let Ok(file) = self.sftp_session.open_file(&new_actual_path, AccessType::O_RDONLY, Mode::empty()) {
				let is_dir = self.get_file_type(&logger, &new_actual_path, &file, info.no_cache())? == SftpFileType::Directory;
				debug!(
					logger, "new name already exists";
					"replace_if_existing" => replace_if_existing,
					"is_dir" => info.is_dir(),
					"new_path_is_dir" => is_dir,
				);
				mem::drop(file);
				if replace_if_existing {
					if !info.is_dir() && !is_dir {
						debug!(logger, "deleting existing file");
						self.sftp_session.delete_file(&new_actual_path)?;
					} else {
						return Err(SshfsError::NtStatus(STATUS_ACCESS_DENIED));
					}
				} else {
					return Err(SshfsError::NtStatus(STATUS_OBJECT_NAME_COLLISION));
				}
			}
			self.invalidate_cache(&logger, &context.path);
			self.invalidate_cache(&logger, &new_actual_path);
			debug!(logger, "moving file");
			self.sftp_session.rename(&context.path, &new_actual_path)?;
			Ok(())
		})
	}

	fn set_end_of_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		self.run("SetEndOfFile", info, Some(context), |logger| {
			debug!(logger, "setting file size"; "size" => offset);
			self.sftp_session.set_file_size(&context.path, offset as u64)?;
			self.update_size_if_in_cache(logger, &context.path, |_| offset as u64);
			Ok(())
		})
	}

	fn set_allocation_size(
		&'b self,
		_file_name: &U16CStr,
		alloc_size: i64,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		self.run("SetAllocationSize", info, Some(context), |logger| {
			debug!(logger, "setting file size"; "size" => alloc_size);
			self.sftp_session.set_file_size(&context.path, alloc_size as u64)?;
			self.update_size_if_in_cache(logger, &context.path, |_| alloc_size as u64);
			Ok(())
		})
	}

	fn get_disk_free_space(&'b self, info: &OperationInfo<'a, 'b, Self>) -> Result<DiskSpaceInfo, OperationError> {
		self.run("GetDiskFreeSpace", info, None, |logger| {
			let stat = self.sftp_session.stat_vfs(".")?;
			let space_info = DiskSpaceInfo {
				byte_count: stat.blocks() * stat.fragment_size(),
				free_byte_count: stat.blocks_free() * stat.fragment_size(),
				available_byte_count: stat.blocks_available() * stat.fragment_size(),
			};
			trace!(logger, "setting total byte count"; "value" => space_info.byte_count);
			trace!(logger, "setting free total byte count"; "value" => space_info.free_byte_count);
			trace!(logger, "setting available byte count"; "value" => space_info.available_byte_count);
			Ok(space_info)
		})
	}

	fn get_volume_information(&'b self, info: &OperationInfo<'a, 'b, Self>) -> Result<VolumeInfo, OperationError> {
		self.run("GetVolumeInformation", info, None, |logger| {
			let stat = self.sftp_session.stat_vfs(".")?;
			trace!(logger, "setting max name length"; "value" => stat.name_max());
			Ok(VolumeInfo {
				name: self.server_name.clone(),
				serial_number: 0,
				max_component_length: stat.name_max() as u32,
				fs_flags: FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_SEQUENTIAL_WRITE_ONCE | FILE_UNICODE_ON_DISK,
				// Custom names (such as "SSHFS") don't play well with UAC.
				fs_name: U16CString::from_str("NTFS").unwrap(),
			})
		})
	}

	fn mounted(&'b self, _info: &OperationInfo<'a, 'b, Self>) -> Result<(), OperationError> {
		info!(self.logger, "mounted");
		Ok(())
	}

	fn unmounted(&'b self, _info: &OperationInfo<'a, 'b, Self>) -> Result<(), OperationError> {
		info!(self.logger, "unmounted");
		Ok(())
	}
}

fn main() {
	let matches = App::new(env!("CARGO_PKG_NAME"))
		.version(env!("YASFW_VERSION"))
		.author(env!("CARGO_PKG_AUTHORS"))
		.about(env!("CARGO_PKG_DESCRIPTION"))
		.arg(Arg::with_name("server").short("s").long("server").takes_value(true).value_name("SERVER_ADDR").required(true).help("SFTP server address."))
		.arg(Arg::with_name("port").short("p").long("port").takes_value(true).value_name("PORT").default_value("22").help("Server port."))
		.arg(Arg::with_name("user").short("u").long("user").takes_value(true).value_name("USER").required(true).help("Username."))
		.arg(Arg::with_name("key").short("k").long("key").takes_value(true).value_name("KEY_FILE").number_of_values(1).multiple(true).help("Private key file."))
		.arg(Arg::with_name("mount_point").short("m").long("mount-point").takes_value(true).value_name("MOUNT_POINT").required(true).help("Mount point path."))
		.arg(Arg::with_name("thread_count").short("t").long("threads").takes_value(true).value_name("THREAD_COUNT").default_value("0").help("Thread count. Use \"0\" to let Dokan choose it automatically."))
		.arg(Arg::with_name("ignore_case").short("i").long("ignore-case").help("Enable support for case-insensitive paths."))
		.arg(Arg::with_name("dokan_debug").short("d").long("dokan-debug").help("Enable Dokan's debug output."))
		.arg(Arg::with_name("removable").short("r").long("removable").help("Mount as a removable drive."))
		.arg(Arg::with_name("log_level").short("l").long("log-level").takes_value(true).default_value("Info").possible_values(&["Error", "Warning", "Info", "Debug", "Trace"]).help("Logging level."))
		.arg(Arg::with_name("auth_only").short("A").long("auth-only").help("Exit immediately after authentication without mounting the volume. (Used for debug purposes.)"))
		.arg(Arg::with_name("use_pageant").short("P").long("use-pageant").help("Try to authenticate using putty's pageant."))
		.arg(Arg::with_name("compress").short("c").long("compress").help("Enable compression."))
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

	if !ssh::init() {
		error!(logger, "ssh_init failed");
		mem::drop(logger);
		process::exit(1);
	}

	let result = (|| -> Result<(), Box<dyn Error>> {
		let server = matches.value_of("server").unwrap();
		let user = matches.value_of("user").unwrap();
		let port = matches.value_of("port").unwrap().parse()?;
		let thread_count = matches.value_of("thread_count").unwrap().parse()?;
		let mount_point = U16CString::from_str(matches.value_of("mount_point").unwrap())?;

		info!(logger, "initializing"; "dokan_version" => dokan::lib_version(), "dokan_driver_version" => dokan::driver_version());
		let mut session = SshSession::new().expect("failed to initialize the SSH session");
		session.set_host(server)?;
		session.set_port(port)?;
		session.set_user(user)?;
		if matches.is_present("compress") {
			session.set_compression(SshCompression::Enabled(SshCompressionAlgorithm::Auto))?;
		}
		session.connect()?;
		if let Some(hash) = session.server_public_key()?.hash(ssh::SshPublicKeyHashType::SHA256) {
			info!(logger, "connected established"; "server_public_key" => hash.hex_string());
		} else {
			error!(logger, "failed to retrieve server public key");
			return Ok(());
		}
		let key_files = matches.values_of("key").map(|v| v.collect::<Vec<_>>());
		let auth_result = auth::do_auth(
			&session,
			matches.is_present("use_pageant"),
			key_files.as_ref().map(|v| v.as_slice()),
			&logger,
		);
		if !auth_result {
			return Ok(());
		}
		if matches.is_present("auth_only") {
			warn!(logger, "returning immediately as --auth-only is specified");
			return Ok(());
		}

		let sftp_session = SftpSession::new(Rc::new(session), logger.clone())?;
		let mut flags = MountFlags::MOUNT_MANAGER | MountFlags::OPTIMIZE_SINGLE_NAME_SEARCH;
		if matches.is_present("dokan_debug") {
			flags |= MountFlags::DEBUG | MountFlags::STDERR;
		}
		if matches.is_present("removable") {
			flags |= MountFlags::REMOVABLE;
		}
		let cloned_logger = Cell::new(Some(logger.clone()));
		let cloned_mount_point = mount_point.clone();
		ctrlc::set_handler(move || {
			let logger = cloned_logger.take();
			if !dokan::unmount(&cloned_mount_point) {
				if let Some(logger) = logger {
					error!(logger, "failed to unmount");
				}
				std::process::exit(1);
			}
		})?;
		let result = Drive::new()
			.thread_count(thread_count)
			.mount_point(&mount_point)
			.flags(flags)
			.mount(&SshfsHandler::new(
				sftp_session,
				logger.clone(),
				U16CString::from_str(format!("{}@{}:{}", user, server, port))?,
				matches.is_present("ignore_case"),
			));
		info!(logger, "exiting"; "dokan_result" => format!("{:?}", result));
		Ok(())
	})();
	if !ssh::finalize() {
		warn!(logger, "ssh_finalize failed");
	}
	if let Err(e) = result {
		error!(logger, "error occurred"; "error" => format!("{:?}", e));
		mem::drop(logger);
		process::exit(1);
	}
}
