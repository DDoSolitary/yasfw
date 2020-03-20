use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt::{self, Display, Formatter};
use std::ptr;
use std::rc::Rc;
use std::sync::Mutex;

use libc::{c_char, c_int, c_uint, c_void, size_t, ssize_t};
use slog::Logger;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
enum SshOptionType {
	Host,
	Port,
	PortStr,
	Fd,
	User,
	SshDir,
	Identity,
	AddIdentity,
	KnownHosts,
	Timeout,
	TimeoutUsec,
	Ssh1,
	Ssh2,
	LogVerbosity,
	LogVerbosityStr,
	CiphersCS,
	CiphersSC,
	CompressionCS,
	CompressionSC,
	ProxyCommand,
	BindAddr,
	StrictHostKeyCheck,
	Compression,
	CompressionLevel,
	KeyExchange,
	HostKeys,
	GssapiServerIdentity,
	GssapiClientIdentity,
	GssapiDelegateCredentials,
	HmacCS,
	HmacSC,
	PasswordAuth,
	PubkeyAuth,
	KbdintAuth,
	GssapiAuth,
	GlobalKnownHosts,
	Nodelay,
	PublicKeyAcceptedTypes,
	ProcessConfig,
	RekeyData,
	RekeyTime,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SshPublicKeyHashType {
	SHA1,
	MD5,
	SHA256,
}

#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SshAuthResult {
	Success = 0,
	Denied,
	Partial,
	Info,
	Again,
	Error = -1,
}

#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SshErrorType {
	NoError,
	RequestDenied,
	Fatal,
	Interrupted,
}

#[repr(u8)]
#[derive(PartialEq, Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SftpFileType {
	Regular = 1,
	Directory,
	Symlink,
	Special,
	Unknown,
}

#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SftpErrorCode {
	Ok,
	Eof,
	NoSuchFile,
	PermissionDenied,
	Failure,
	BadMessage,
	NoConnection,
	ConnectionLost,
	OpUnsupported,
	InvalidHandle,
	NoSuchPath,
	FileAlreadyExists,
	WriteProtect,
	NoMedia,
	NoSpaceOnFilesystem,
	QuotaExceeded,
	UnknownPrinciple,
	LockConflict,
	DirNotEmpty,
	NotADirectory,
	InvalidFileName,
	LinkLoop,
	CannotDelete,
	InvalidParameter,
	FileIsADirectory,
	ByteRangeLockConflict,
	ByteRangeLockRefused,
	DeletePending,
	FileCorrupt,
	OwnerInvalid,
	GroupInvalid,
	NoMatchingByteRangeLock,
}

bitflags! {
	#[repr(transparent)]
	pub struct SshAuthMethod : i32 {
		const UNKNOWN = 0;
		const NONE = 1;
		const PASSWORD = 2;
		const PUBLICKEY = 4;
		const HOSTBASED = 8;
		const INTERACTIVE = 16;
		const GSSAPI_MIC = 32;
	}
}

bitflags! {
	#[repr(transparent)]
	pub struct AccessType : i32 {
		const O_RDONLY = libc::O_RDONLY;
		const O_WRONLY = libc::O_WRONLY;
		const O_RDWR = libc::O_RDWR;
		const O_CREAT = libc::O_CREAT;
		const O_TRUNC = libc::O_TRUNC;
	}
}

bitflags! {
	#[repr(transparent)]
	pub struct Mode : u32 {
		const S_ISUID = 2048;
		const S_ISGID = 1024;
		const S_ISVTX = 512;
		const S_IRUSR = 256;
		const S_IWUSR = 128;
		const S_IXUSR = 64;
		const S_IRWXU = Self::S_IXUSR.bits | Self::S_IWUSR.bits | Self::S_IRUSR.bits;
		const S_IRGRP = 32;
		const S_IWGRP = 16;
		const S_IXGRP = 8;
		const S_IRWXG = Self::S_IXGRP.bits | Self::S_IWGRP.bits | Self::S_IRGRP.bits;
		const S_IROTH = 4;
		const S_IWOTH = 2;
		const S_IXOTH = 1;
		const S_IRWXO = Self::S_IXOTH.bits | Self::S_IWOTH.bits | Self::S_IROTH.bits;
	}
}

bitflags! {
	#[repr(transparent)]
	struct SftpAttributeFlags : u32 {
		const SIZE = 0x00000001;
		const UIDGID = 0x00000002;
		const PERMISSIONS = 0x00000004;
		const ACMODTIME =  0x00000008;
		const ACCESSTIME =  0x00000008;
		const CREATETIME = 0x00000010;
		const MODIFYTIME = 0x00000020;
		const ACL = 0x00000040;
		const OWNERGROUP = 0x00000080;
		const SUBSECOND_TIMES = 0x00000100;
		const EXTENDED = 0x80000000;
	}
}

#[repr(C)]
struct CSshSession { _private: [u8; 0] }

#[repr(C)]
struct CSshKey { _private: [u8; 0] }

#[repr(C)]
struct CSftpSession { _private: [u8; 0] }

#[repr(C)]
struct CSftpDirectory { _private: [u8; 0] }

#[repr(C)]
struct CSftpFile { _private: [u8; 0] }

#[repr(C)]
#[derive(Debug)]
struct CStatVfs {
	block_size: u64,
	fragment_size: u64,
	blocks: u64,
	blocks_free: u64,
	blocks_available: u64,
	files: u64,
	files_free: u64,
	files_available: u64,
	filesystem_id: u64,
	flag: u64,
	name_max: u64,
}

#[repr(C)]
struct SshString {
	size: u32,
	data: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
struct CSftpAttributes {
	name: *const c_char,
	longname: *const c_char,
	flags: SftpAttributeFlags,
	file_type: SftpFileType,
	size: u64,
	uid: u32,
	gid: u32,
	owner: *const c_char,
	group: *const c_char,
	permissions: Mode,
	atime64: u64,
	atime: u32,
	atime_nseconds: u32,
	createtime: u64,
	createtime_nseconds: u32,
	mtime64: u64,
	mtime: u32,
	mtime_nseconds: u32,
	acl: *const SshString,
	extended_count: u32,
	extended_type: *const SshString,
	extended_data: *const SshString,
}

type SshAuthCallback = extern fn(*const c_char, *mut c_char, size_t, c_int, c_int, *mut c_void) -> c_int;

extern {
	#[cfg(libssh_static)]
	fn ssh_init() -> c_int;
	#[cfg(libssh_static)]
	fn ssh_finalize() -> c_int;
	fn ssh_new() -> *const CSshSession;
	fn ssh_free(session: *const CSshSession);
	fn ssh_options_set(session: *const CSshSession, option: SshOptionType, value: *const c_void) -> c_int;
	fn ssh_connect(session: *const CSshSession) -> c_int;
	fn ssh_disconnect(session: *const CSshSession);
	fn ssh_get_error(session: *const CSshSession) -> *const c_char;
	fn ssh_get_error_code(session: *const CSshSession) -> SshErrorType;
	fn ssh_get_server_publickey(session: *const CSshSession, key: *mut *const CSshKey) -> c_int;
	fn ssh_pki_import_privkey_file(filename: *const c_char, passphrase: *const c_char, auth_fn: Option<SshAuthCallback>, auth_data: *mut c_void, pkey: *mut *const CSshKey) -> c_int;
	fn ssh_key_free(key: *const CSshKey);
	fn ssh_get_publickey_hash(key: *const CSshKey, hash_type: SshPublicKeyHashType, hash: *mut *const u8, hlen: *mut size_t) -> c_int;
	fn ssh_clean_pubkey_hash(hash: *mut *const u8);
	fn ssh_userauth_list(session: *const CSshSession, username: *const c_char) -> SshAuthMethod;
	fn ssh_userauth_none(session: *const CSshSession, username: *const c_char) -> SshAuthResult;
	fn ssh_userauth_publickey(session: *const CSshSession, username: *const c_char, privkey: *const CSshKey) -> SshAuthResult;
	fn ssh_userauth_password(session: *const CSshSession, username: *const c_char, password: *const c_char) -> SshAuthResult;
	fn ssh_userauth_kbdint(session: *const CSshSession, username: *const c_char, submethods: *const c_char) -> SshAuthResult;
	fn ssh_userauth_kbdint_getname(session: *const CSshSession) -> *const c_char;
	fn ssh_userauth_kbdint_getinstruction(session: *const CSshSession) -> *const c_char;
	fn ssh_userauth_kbdint_getnprompts(session: *const CSshSession) -> c_int;
	fn ssh_userauth_kbdint_getprompt(session: *const CSshSession, i: c_uint, echo: *mut c_char) -> *const c_char;
	fn ssh_userauth_kbdint_setanswer(session: *const CSshSession, i: c_uint, answer: *const c_char) -> c_int;
	fn sftp_new(session: *const CSshSession) -> *const CSftpSession;
	fn sftp_free(sftp: *const CSftpSession);
	fn sftp_init(sftp: *const CSftpSession) -> c_int;
	fn sftp_server_version(sftp: *const CSftpSession) -> c_int;
	fn sftp_get_error(sftp: *const CSftpSession) -> SftpErrorCode;
	fn sftp_statvfs(sftp: *const CSftpSession, path: *const c_char) -> *const CStatVfs;
	fn sftp_statvfs_free(statvfs_o: *const CStatVfs);
	fn sftp_opendir(sftp: *const CSftpSession, path: *const c_char) -> *const CSftpDirectory;
	fn sftp_closedir(dir: *const CSftpDirectory) -> c_int;
	fn sftp_readdir(sftp: *const CSftpSession, dir: *const CSftpDirectory) -> *const CSftpAttributes;
	fn sftp_dir_eof(dir: *const CSftpDirectory) -> c_int;
	fn sftp_open(sftp: *const CSftpSession, path: *const c_char, accesstype: AccessType, mode: Mode) -> *const CSftpFile;
	fn sftp_close(file: *const CSftpFile) -> c_int;
	fn sftp_fstat(file: *const CSftpFile) -> *const CSftpAttributes;
	fn sftp_read(file: *const CSftpFile, buf: *mut u8, count: size_t) -> ssize_t;
	fn sftp_write(file: *const CSftpFile, buf: *const u8, count: size_t) -> ssize_t;
	fn sftp_seek64(file: *const CSftpFile, new_offset: u64) -> c_int;
	fn sftp_unlink(sftp: *const CSftpSession, file: *const c_char) -> c_int;
	fn sftp_rmdir(sftp: *const CSftpSession, directory: *const c_char) -> c_int;
	fn sftp_mkdir(sftp: *const CSftpSession, directory: *const c_char, mode: Mode) -> c_int;
	fn sftp_rename(sftp: *const CSftpSession, original: *const c_char, newname: *const c_char) -> c_int;
	fn sftp_setstat(sftp: *const CSftpSession, file: *const c_char, attr: *const CSftpAttributes) -> c_int;
	fn sftp_attributes_free(file: *const CSftpAttributes);
}

pub struct SshSession {
	session_ptr: *const CSshSession,
	connected: bool,
	mutex: Mutex<()>,
}

unsafe impl Send for SshSession {}

unsafe impl Sync for SshSession {}

#[derive(Debug)]
pub struct SshError {
	error_type: SshErrorType,
	error_msg: String,
	sftp_error_code: Option<SftpErrorCode>,
}

pub struct SshKey {
	key_ptr: *const CSshKey,
}

unsafe impl Send for SshKey {}

unsafe impl Sync for SshKey {}

pub struct SshPublicKeyHash {
	buffer_ptr: *const u8,
	buffer_len: usize,
}

unsafe impl Send for SshPublicKeyHash {}

unsafe impl Sync for SshPublicKeyHash {}

#[derive(Debug, Clone)]
pub struct SshKbdIntQuestion {
	pub prompt: String,
	pub echo: bool,
}

#[derive(Debug, Clone)]
pub struct SshKbdIntInfo {
	pub name: String,
	pub instruction: String,
	pub questions: Vec<SshKbdIntQuestion>,
}

#[derive(Debug, Clone)]
pub enum SshKbdIntResult {
	AuthInfo(SshKbdIntInfo),
	AuthResult(SshAuthResult),
}

pub struct SftpSession {
	session: Rc<SshSession>,
	sftp_ptr: *const CSftpSession,
	logger: Logger,
}

unsafe impl Send for SftpSession {}

unsafe impl Sync for SftpSession {}

pub struct StatVfs {
	stat_ptr: *const CStatVfs,
}

unsafe impl Send for StatVfs {}

unsafe impl Sync for StatVfs {}

pub struct SftpDirectoryIterator<'a> {
	session: &'a SftpSession,
	dir_ptr: *const CSftpDirectory,
	error_occurred: bool,
}

unsafe impl Send for SftpDirectoryIterator<'_> {}

unsafe impl Sync for SftpDirectoryIterator<'_> {}

pub struct SftpFile<'a> {
	session: &'a SftpSession,
	file_ptr: *const CSftpFile,
}

unsafe impl Send for SftpFile<'_> {}

unsafe impl Sync for SftpFile<'_> {}

pub struct SftpAttributes<'a> {
	session: &'a SftpSession,
	attr_ptr: *const CSftpAttributes,
}

unsafe impl Send for SftpAttributes<'_> {}

unsafe impl Sync for SftpAttributes<'_> {}

pub type SshResult<T> = Result<T, SshError>;

impl SshSession {
	pub fn new() -> Option<SshSession> {
		let ptr = unsafe { ssh_new() };
		if ptr.is_null() {
			None
		} else {
			Some(SshSession { session_ptr: ptr, connected: false, mutex: Mutex::new(()) })
		}
	}

	fn last_error_unlocked(&self) -> SshError {
		unsafe {
			SshError {
				error_type: ssh_get_error_code(self.session_ptr),
				error_msg: CStr::from_ptr(ssh_get_error(self.session_ptr)).to_string_lossy().into_owned(),
				sftp_error_code: None,
			}
		}
	}

	// Caller must acquire the mutex;
	fn check_error(&self, result: bool) -> SshResult<()> {
		if result { Ok(()) } else { Err(self.last_error_unlocked()) }
	}

	// Caller must acquire the mutex;
	fn check_error_code(&self, code: c_int) -> SshResult<()> {
		self.check_error(code >= 0)
	}

	pub fn last_error(&self) -> SshError {
		let _guard = self.mutex.lock().unwrap();
		self.last_error_unlocked()
	}

	pub fn connect(&mut self) -> SshResult<()> {
		let _guard = self.mutex.lock().unwrap();
		self.check_error_code(unsafe { ssh_connect(self.session_ptr) })?;
		self.connected = true;
		Ok(())
	}

	pub fn disconnect(&mut self) {
		let _guard = self.mutex.lock().unwrap();
		unsafe { ssh_disconnect(self.session_ptr); }
		self.connected = false
	}

	pub fn set_host(&self, host: &str) -> SshResult<()> {
		let c_host = CString::new(host).unwrap();
		let _guard = self.mutex.lock().unwrap();
		self.check_error_code(unsafe {
			ssh_options_set(
				self.session_ptr,
				SshOptionType::Host,
				c_host.as_ptr() as *const c_void,
			)
		})?;
		Ok(())
	}

	pub fn set_port(&self, port: u32) -> SshResult<()> {
		let _guard = self.mutex.lock().unwrap();
		self.check_error_code(unsafe {
			ssh_options_set(
				self.session_ptr,
				SshOptionType::Port,
				&port as *const u32 as *const c_void,
			)
		})?;
		Ok(())
	}

	pub fn set_user(&self, user: &str) -> SshResult<()> {
		let c_user = CString::new(user).unwrap();
		let _guard = self.mutex.lock().unwrap();
		self.check_error_code(unsafe {
			ssh_options_set(
				self.session_ptr,
				SshOptionType::User,
				c_user.as_ptr() as *const c_void,
			)
		})
	}

	pub fn server_public_key(&self) -> SshResult<SshKey> {
		let mut ptr = ptr::null();
		let _guard = self.mutex.lock().unwrap();
		self.check_error_code(unsafe { ssh_get_server_publickey(self.session_ptr, &mut ptr) })?;
		Ok(SshKey { key_ptr: ptr })
	}

	pub fn auth_method_list(&self) -> SshAuthMethod {
		let _guard = self.mutex.lock().unwrap();
		unsafe { ssh_userauth_list(self.session_ptr, ptr::null()) }
	}

	pub fn auth_none(&self) -> SshAuthResult {
		let _guard = self.mutex.lock().unwrap();
		unsafe { ssh_userauth_none(self.session_ptr, ptr::null()) }
	}

	pub fn auth_public_key(&self, key: &SshKey) -> SshAuthResult {
		let _guard = self.mutex.lock().unwrap();
		unsafe { ssh_userauth_publickey(self.session_ptr, ptr::null(), key.key_ptr) }
	}

	pub fn auth_password(&self, password: &str) -> SshAuthResult {
		let c_password = CString::new(password).unwrap();
		let _guard = self.mutex.lock().unwrap();
		unsafe { ssh_userauth_password(self.session_ptr, ptr::null(), c_password.as_ptr()) }
	}

	pub fn auth_kbdint(&self) -> SshKbdIntResult {
		let _guard = self.mutex.lock().unwrap();
		unsafe {
			let res = ssh_userauth_kbdint(self.session_ptr, ptr::null(), ptr::null());
			if res != SshAuthResult::Info { SshKbdIntResult::AuthResult(res) } else {
				let c_name = ssh_userauth_kbdint_getname(self.session_ptr);
				let c_instruction = ssh_userauth_kbdint_getinstruction(self.session_ptr);
				let mut info = SshKbdIntInfo {
					name: CStr::from_ptr(c_name).to_string_lossy().into(),
					instruction: CStr::from_ptr(c_instruction).to_string_lossy().into(),
					questions: Vec::new(),
				};
				for i in 0..ssh_userauth_kbdint_getnprompts(self.session_ptr) as c_uint {
					let mut echo = 0;
					let c_prompt = ssh_userauth_kbdint_getprompt(self.session_ptr, i, &mut echo);
					info.questions.push(SshKbdIntQuestion {
						prompt: CStr::from_ptr(c_prompt).to_string_lossy().into(),
						echo: echo != 0,
					})
				}
				SshKbdIntResult::AuthInfo(info)
			}
		}
	}

	pub fn auth_kbdint_set_answer(&self, index: u32, answer: &str) -> SshResult<()> {
		let c_answer = CString::new(answer).unwrap();
		self.check_error_code(unsafe {
			ssh_userauth_kbdint_setanswer(self.session_ptr, index, c_answer.as_ptr())
		})
	}
}

impl Drop for SshSession {
	fn drop(&mut self) {
		if self.connected { self.disconnect() }
		let _guard = self.mutex.lock().unwrap();
		unsafe { ssh_free(self.session_ptr); }
	}
}

impl SshError {
	pub fn sftp_error_code(&self) -> Option<SftpErrorCode> {
		self.sftp_error_code
	}
}

impl Error for SshError {}

impl Display for SshError {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		write!(f, "{:?}", self)
	}
}

extern fn auth_passphrase_fn<F: FnOnce(&str) -> Option<String>>(
	prompt: *const c_char,
	buf: *mut c_char,
	len: size_t,
	_echo: c_int,
	_verify: c_int,
	userdata: *mut c_void,
) -> c_int {
	unsafe {
		let passphrase_callback = Box::from_raw(userdata as *mut F);
		let prompt = CStr::from_ptr(prompt).to_str().unwrap();
		let passphrase = if let Some(passphrase) = passphrase_callback(&prompt) {
			CString::new(passphrase).unwrap()
		} else {
			// SSH_ERROR
			return -1;
		};
		let input_len = passphrase.as_bytes_with_nul().len();
		if input_len > len {
			// SSH_ERROR
			return -1;
		}
		ptr::copy(passphrase.as_ptr(), buf, input_len);
	}
	// SSH_OK
	0
}

impl SshKey {
	pub fn from_private_key_file<F: FnOnce(&str) -> Option<String>>(filename: &str, auth_fn: F) -> Option<SshKey> {
		let c_filename = CString::new(filename).unwrap();
		let mut key_ptr = ptr::null();
		let result = unsafe {
			ssh_pki_import_privkey_file(
				c_filename.as_ptr(), ptr::null(),
				Some(auth_passphrase_fn::<F>), Box::into_raw(Box::new(auth_fn)) as *mut c_void,
				&mut key_ptr,
			)
		};
		if result == 0 { Some(SshKey { key_ptr }) } else { None }
	}

	pub fn hash(&self, hash_type: SshPublicKeyHashType) -> Option<SshPublicKeyHash> {
		let mut hash = SshPublicKeyHash {
			buffer_ptr: ptr::null(),
			buffer_len: 0,
		};
		let result = unsafe {
			ssh_get_publickey_hash(
				self.key_ptr, hash_type,
				&mut hash.buffer_ptr, &mut hash.buffer_len,
			)
		};
		if result == 0 { Some(hash) } else { None }
	}
}

impl Drop for SshKey {
	fn drop(&mut self) {
		unsafe { ssh_key_free(self.key_ptr); }
	}
}

impl SshPublicKeyHash {
	pub fn hex_string(&self) -> String {
		(0..self.buffer_len)
			.map(|i| unsafe { *self.buffer_ptr.offset(i as isize) })
			.map(|x| format!("{:02X}", x))
			.collect::<Vec<String>>().join(":")
	}
}

impl Drop for SshPublicKeyHash {
	fn drop(&mut self) {
		unsafe { ssh_clean_pubkey_hash(&mut self.buffer_ptr); }
	}
}

impl SftpSession {
	pub fn new(session: Rc<SshSession>, logger: Logger) -> SshResult<SftpSession> {
		let ptr = {
			let _guard = session.mutex.lock();
			let ptr = unsafe { sftp_new(session.session_ptr) };
			session.check_error(!ptr.is_null())?;
			session.check_error_code(unsafe { sftp_init(ptr) })?;
			ptr
		};
		Ok(SftpSession { session, sftp_ptr: ptr, logger })
	}

	// Caller must acquire the mutex.
	fn check_error(&self, result: bool) -> SshResult<()> {
		self.session.check_error(result).map_err(|e| SshError {
			sftp_error_code: Some(unsafe { sftp_get_error(self.sftp_ptr) }),
			..e
		})?;
		Ok(())
	}

	fn check_error_code(&self, code: c_int) -> SshResult<()> {
		self.check_error(code >= 0)
	}

	pub fn server_version(&self) -> c_int {
		let _guard = self.session.mutex.lock().unwrap();
		unsafe { sftp_server_version(self.sftp_ptr) }
	}

	pub fn stat_vfs(&self, path: &str) -> SshResult<StatVfs> {
		let c_path = CString::new(path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		let ptr = unsafe { sftp_statvfs(self.sftp_ptr, c_path.as_ptr()) };
		self.check_error(!ptr.is_null())?;
		Ok(StatVfs { stat_ptr: ptr })
	}

	pub fn open_directory(&self, path: &str) -> SshResult<SftpDirectoryIterator> {
		let c_path = CString::new(path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		let ptr = unsafe { sftp_opendir(self.sftp_ptr, c_path.as_ptr()) };
		self.check_error(!ptr.is_null())?;
		Ok(SftpDirectoryIterator { session: self, dir_ptr: ptr, error_occurred: false })
	}

	pub fn open_file(&self, path: &str, access_type: AccessType, mode: Mode) -> SshResult<SftpFile> {
		let c_path = CString::new(path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		let ptr = unsafe { sftp_open(self.sftp_ptr, c_path.as_ptr(), access_type, mode) };
		self.check_error(!ptr.is_null())?;
		Ok(SftpFile { session: self, file_ptr: ptr })
	}

	pub fn delete_file(&self, path: &str) -> SshResult<()> {
		let c_path = CString::new(path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		self.check_error_code(unsafe { sftp_unlink(self.sftp_ptr, c_path.as_ptr()) })
	}

	pub fn create_directory(&self, path: &str, mode: Mode) -> SshResult<()> {
		let c_path = CString::new(path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		self.check_error_code(unsafe { sftp_mkdir(self.sftp_ptr, c_path.as_ptr(), mode) })
	}

	pub fn delete_directory(&self, path: &str) -> SshResult<()> {
		let c_path = CString::new(path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		self.check_error_code(unsafe { sftp_rmdir(self.sftp_ptr, c_path.as_ptr()) })
	}

	pub fn rename(&self, old_path: &str, new_path: &str) -> SshResult<()> {
		let c_old_path = CString::new(old_path).unwrap();
		let c_new_path = CString::new(new_path).unwrap();
		let _guard = self.session.mutex.lock().unwrap();
		self.check_error_code(unsafe {
			sftp_rename(self.sftp_ptr, c_old_path.as_ptr(), c_new_path.as_ptr())
		})
	}

	pub fn set_file_size(&self, path: &str, new_size: u64) -> SshResult<()> {
		let c_path = CString::new(path).unwrap();
		let attr = CSftpAttributes {
			flags: SftpAttributeFlags::SIZE,
			size: new_size,
			..CSftpAttributes::new()
		};
		let _guard = self.session.mutex.lock().unwrap();
		self.check_error_code(unsafe { sftp_setstat(self.sftp_ptr, c_path.as_ptr(), &attr) })
	}

	pub fn set_file_time(&self, path: &str, atime: u64, atime_nsec: u32, create_time: u64, create_time_nsec: u32, mtime: u64, mtime_nsec: u32) -> SshResult<()> {
		let c_path = CString::new(path).unwrap();
		let attr = if self.server_version() <= 3 {
			CSftpAttributes {
				flags: SftpAttributeFlags::ACMODTIME,
				atime: atime as u32,
				mtime: mtime as u32,
				..CSftpAttributes::new()
			}
		} else {
			CSftpAttributes {
				flags: SftpAttributeFlags::ACCESSTIME | SftpAttributeFlags::CREATETIME | SftpAttributeFlags::MODIFYTIME | SftpAttributeFlags::SUBSECOND_TIMES,
				atime64: atime,
				atime_nseconds: atime_nsec,
				createtime: create_time,
				createtime_nseconds: create_time_nsec,
				mtime64: mtime,
				mtime_nseconds: mtime_nsec,
				..CSftpAttributes::new()
			}
		};
		let _guard = self.session.mutex.lock().unwrap();
		self.check_error_code(unsafe { sftp_setstat(self.sftp_ptr, c_path.as_ptr(), &attr) })
	}
}

impl Drop for SftpSession {
	fn drop(&mut self) {
		let _guard = self.session.mutex.lock().unwrap();
		unsafe { sftp_free(self.sftp_ptr) }
	}
}

impl StatVfs {
	pub fn fragment_size(&self) -> u64 { unsafe { (&*self.stat_ptr).fragment_size } }

	pub fn blocks(&self) -> u64 { unsafe { (&*self.stat_ptr).blocks } }

	pub fn blocks_free(&self) -> u64 { unsafe { (&*self.stat_ptr).blocks_free } }

	pub fn blocks_available(&self) -> u64 { unsafe { (&*self.stat_ptr).blocks_available } }

	pub fn name_max(&self) -> u64 { unsafe { (&*self.stat_ptr).name_max } }
}

impl Drop for StatVfs {
	fn drop(&mut self) { unsafe { sftp_statvfs_free(self.stat_ptr) } }
}

impl<'a> Iterator for SftpDirectoryIterator<'a> {
	type Item = SshResult<SftpAttributes<'a>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.error_occurred {
			return None;
		}
		let _guard = self.session.session.mutex.lock().unwrap();
		let ptr = unsafe { sftp_readdir(self.session.sftp_ptr, self.dir_ptr) };
		if unsafe { sftp_dir_eof(self.dir_ptr) } == 0 {
			let result = self.session.check_error(!ptr.is_null()).map(|_| SftpAttributes {
				session: self.session,
				attr_ptr: ptr,
			});
			if result.is_err() {
				self.error_occurred = true;
			}
			Some(result)
		} else {
			None
		}
	}
}

impl Drop for SftpDirectoryIterator<'_> {
	fn drop(&mut self) {
		let _guard = self.session.session.mutex.lock().unwrap();
		if let Err(e) = self.session.check_error_code(unsafe { sftp_closedir(self.dir_ptr) }) {
			error!(self.session.logger, "failed to close the directory"; "error" => format!("{:?}", e));
		}
	}
}

impl SftpFile<'_> {
	pub fn attributes(&self) -> SshResult<SftpAttributes> {
		let _guard = self.session.session.mutex.lock().unwrap();
		let ptr = unsafe { sftp_fstat(self.file_ptr) };
		self.session.check_error(!ptr.is_null())?;
		Ok(SftpAttributes { session: self.session, attr_ptr: ptr })
	}

	// Caller must acquire the mutex.
	fn seek(&self, offset: u64) -> SshResult<()> {
		self.session.check_error_code(unsafe { sftp_seek64(self.file_ptr, offset) })
	}

	pub fn read(&self, offset: u64, buf: &mut [u8]) -> SshResult<u64> {
		let _guard = self.session.session.mutex.lock().unwrap();
		self.seek(offset)?;
		let bytes_read = unsafe { sftp_read(self.file_ptr, buf.as_mut_ptr(), buf.len()) };
		self.session.check_error(bytes_read >= 0)?;
		Ok(bytes_read as u64)
	}

	pub fn write(&self, offset: u64, buf: &[u8]) -> SshResult<u64> {
		let _guard = self.session.session.mutex.lock().unwrap();
		self.seek(offset)?;
		let bytes_written = unsafe { sftp_write(self.file_ptr, buf.as_ptr(), buf.len()) };
		self.session.check_error(bytes_written >= 0)?;
		Ok(bytes_written as u64)
	}
}

impl Drop for SftpFile<'_> {
	fn drop(&mut self) {
		let _guard = self.session.session.mutex.lock().unwrap();
		if let Err(e) = self.session.check_error_code(unsafe { sftp_close(self.file_ptr) }) {
			error!(self.session.logger, "failed to close the file"; "error" => format!("{:?}", e));
		}
	}
}

impl CSftpAttributes {
	fn new() -> CSftpAttributes {
		CSftpAttributes {
			name: ptr::null(),
			longname: ptr::null(),
			flags: SftpAttributeFlags::empty(),
			file_type: SftpFileType::Regular,
			size: 0,
			uid: 0,
			gid: 0,
			owner: ptr::null(),
			group: ptr::null(),
			permissions: Mode::empty(),
			atime64: 0,
			atime: 0,
			atime_nseconds: 0,
			createtime: 0,
			createtime_nseconds: 0,
			mtime64: 0,
			mtime: 0,
			mtime_nseconds: 0,
			acl: ptr::null(),
			extended_count: 0,
			extended_type: ptr::null(),
			extended_data: ptr::null(),
		}
	}
}

impl SftpAttributes<'_> {
	fn attr(&self) -> &CSftpAttributes {
		unsafe { &*self.attr_ptr }
	}

	pub fn name(&self) -> Option<&str> {
		let ptr = self.attr().name;
		if ptr.is_null() {
			None
		} else {
			Some(unsafe { CStr::from_ptr(ptr).to_str().unwrap() })
		}
	}

	pub fn size(&self) -> Option<u64> {
		if self.attr().flags.contains(SftpAttributeFlags::SIZE) {
			Some(self.attr().size)
		} else {
			None
		}
	}

	pub fn file_type(&self) -> SftpFileType {
		self.attr().file_type
	}

	pub fn atime(&self) -> Option<u64> {
		if self.session.server_version() <= 3 {
			if self.attr().flags.contains(SftpAttributeFlags::ACMODTIME) {
				Some(self.attr().atime.into())
			} else {
				None
			}
		} else if self.attr().flags.contains(SftpAttributeFlags::ACCESSTIME) {
			Some(self.attr().atime64)
		} else {
			None
		}
	}

	pub fn atime_nsec(&self) -> Option<u32> {
		if self.attr().flags.contains(SftpAttributeFlags::ACCESSTIME | SftpAttributeFlags::SUBSECOND_TIMES) {
			Some(self.attr().atime_nseconds)
		} else {
			None
		}
	}

	pub fn create_time(&self) -> Option<u64> {
		if self.attr().flags.contains(SftpAttributeFlags::CREATETIME) {
			Some(self.attr().createtime)
		} else {
			None
		}
	}

	pub fn create_time_nsec(&self) -> Option<u32> {
		if self.attr().flags.contains(SftpAttributeFlags::CREATETIME | SftpAttributeFlags::SUBSECOND_TIMES) {
			Some(self.attr().createtime_nseconds)
		} else {
			None
		}
	}

	pub fn mtime(&self) -> Option<u64> {
		if self.session.server_version() <= 3 {
			if self.attr().flags.contains(SftpAttributeFlags::ACMODTIME) {
				Some(self.attr().mtime.into())
			} else {
				None
			}
		} else if self.attr().flags.contains(SftpAttributeFlags::MODIFYTIME) {
			Some(self.attr().mtime64)
		} else {
			None
		}
	}

	pub fn mtime_nsec(&self) -> Option<u32> {
		if self.attr().flags.contains(SftpAttributeFlags::MODIFYTIME | SftpAttributeFlags::SUBSECOND_TIMES) {
			Some(self.attr().mtime_nseconds)
		} else {
			None
		}
	}
}

impl Drop for SftpAttributes<'_> {
	fn drop(&mut self) { unsafe { sftp_attributes_free(self.attr_ptr) } }
}

pub fn init() -> bool {
	#[cfg(libssh_static)]
		unsafe { ssh_init() == 0 }
	#[cfg(not(libssh_static))]
		true
}

pub fn finalize() -> bool {
	#[cfg(libssh_static)]
		unsafe { ssh_finalize() == 0 }
	#[cfg(not(libssh_static))]
		true
}
