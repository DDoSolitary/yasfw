use std::io;
use slog::Logger;
use super::ssh::*;

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
enum AuthState {
	Partial,
	Success,
	Denied,
}

#[derive(Debug)]
enum AuthErrorReason {
	UnexpectedResult(SshAuthResult),
	SshError(SshError),
	Denied,
	LoadKeyFailed,
	ReadPasswordFailed(io::Error),
}

#[derive(Debug)]
struct AuthError {
	reason: AuthErrorReason,
	auth_list: SshAuthMethod,
}

fn check_auth_result(session: &SshSession, res: SshAuthResult, auth_list: SshAuthMethod) -> Result<AuthState, AuthError> {
	match res {
		SshAuthResult::Partial => Ok(AuthState::Partial),
		SshAuthResult::Success => Ok(AuthState::Success),
		SshAuthResult::Denied => Ok(AuthState::Denied),
		SshAuthResult::Error => Err(AuthError {
			reason: AuthErrorReason::SshError(session.last_error()),
			auth_list,
		}),
		_ => Err(AuthError {
			reason: AuthErrorReason::UnexpectedResult(res),
			auth_list,
		}),
	}
}

fn try_pubkey_auth(
	session: &SshSession,
	auth_list: SshAuthMethod,
	key_files: &[&str],
	logger: &Logger,
) -> Result<AuthState, AuthError> {
	let mut state = AuthState::Denied;
	for key_file in key_files {
		let logger = logger.new(o!("key_file" => (*key_file).to_owned()));
		debug!(logger, "trying public key authentication");
		let key = SshKey::from_private_key_file(key_file, |prompt| {
			let prompt = format!("{} for \"{}\": ", prompt, key_file);
			rpassword::prompt_password_stdout(&prompt).ok()
		});
		if let Some(key) = key {
			let current_state = check_auth_result(
				session, session.auth_public_key(&key), auth_list,
			)?;
			if current_state == AuthState::Denied {
				debug!(logger, "the key is denied by server");
			} else {
				debug!(logger, "the key is accepted by server");
				state = current_state;
				break;
			}
		} else {
			return Err(AuthError { reason: AuthErrorReason::LoadKeyFailed, auth_list });
		}
	}
	Ok(state)
}

fn try_kbdint_auth(session: &SshSession, auth_list: SshAuthMethod, logger: &Logger) -> Result<AuthState, AuthError> {
	loop {
		debug!(logger, "trying keyboard interactive authentication");
		match session.auth_kbdint() {
			SshKbdIntResult::AuthInfo(info) => {
				debug!(logger, "authentication information received.");
				if !info.name.is_empty() {
					println!("Authentication name: {}", info.name);
				}
				if !info.instruction.is_empty() {
					println!("Authentication instruction:\n{}", info.instruction);
				}
				for (i, question) in info.questions.iter().enumerate() {
					let answer = rpassword::prompt_password_stdout(&question.prompt)
						.map_err(|e| AuthError { reason: AuthErrorReason::ReadPasswordFailed(e), auth_list })?;
					session.auth_kbdint_set_answer(i as u32, &answer)
						.map_err(|e| AuthError { reason: AuthErrorReason::SshError(e), auth_list })?;
				}
			}
			SshKbdIntResult::AuthResult(res) => {
				debug!(logger, "authentication result received");
				return check_auth_result(session, res, auth_list);
			}
		}
	}
}

fn try_password_auth(session: &SshSession, auth_list: SshAuthMethod, logger: &Logger) -> Result<AuthState, AuthError> {
	debug!(logger, "trying password authentication");
	let password = rpassword::prompt_password_stdout("Password: ")
		.map_err(|e| AuthError { reason: AuthErrorReason::ReadPasswordFailed(e), auth_list })?;
	check_auth_result(session, session.auth_password(&password), auth_list)
}

fn do_auth_internal(session: &SshSession, key_files: Option<&[&str]>, logger: &Logger) -> Result<(), AuthError> {
	loop {
		debug!(logger, "trying none authentication");
		match check_auth_result(session, session.auth_none(), SshAuthMethod::UNKNOWN)? {
			AuthState::Partial => {
				info!(logger, "partially authenticated using none authentication");
				continue;
			}
			AuthState::Success => {
				info!(logger, "none authentication succeeded");
				break;
			}
			AuthState::Denied => debug!(logger, "none authentication denied"),
		}

		let auth_list = session.auth_method_list();
		debug!(
			logger, "server authentication methods retrieved";
			"server_auth_methods" => format!("{:?}", auth_list)
		);

		if let Some(key_files) = key_files {
			if auth_list.contains(SshAuthMethod::PUBLICKEY) {
				match try_pubkey_auth(session, auth_list, key_files, logger)? {
					AuthState::Partial => {
						info!(logger, "partially authenticated using public key");
						continue;
					}
					AuthState::Success => {
						info!(logger, "public key authentication succeeded");
						break;
					}
					AuthState::Denied => info!(logger, "all keys are denied by server"),
				}
			} else {
				info!(logger, "key file is provided but server doesn't allow public key authentication");
			}
		}

		if auth_list.contains(SshAuthMethod::INTERACTIVE) {
			match try_kbdint_auth(session, auth_list, logger)? {
				AuthState::Partial => {
					info!(logger, "partially authenticated using keyboard interactive authentication");
					continue;
				}
				AuthState::Success => {
					info!(logger, "keyboard interactive authentication succeeded");
					break;
				}
				AuthState::Denied => info!(logger, "keyboard interactive answers are denied by server"),
			}
		}

		if auth_list.contains(SshAuthMethod::PASSWORD) {
			match try_password_auth(session, auth_list, logger)? {
				AuthState::Partial => {
					info!(logger, "partially authenticated using password");
					continue;
				}
				AuthState::Success => {
					info!(logger, "password authentication succeeded");
					break;
				}
				AuthState::Denied => info!(logger, "password is denied by server"),
			}
		} else {
			debug!(logger, "password authentication is not allowed by server")
		}

		return Err(AuthError { reason: AuthErrorReason::Denied, auth_list });
	}
	Ok(())
}

pub fn do_auth(session: &SshSession, key_files: Option<&[&str]>, logger: &Logger) -> bool {
	if let Err(e) = do_auth_internal(session, key_files, logger) {
		let logger = logger.new(o!("server_auth_methods" => format!("{:?}", e.auth_list)));
		match e.reason {
			AuthErrorReason::UnexpectedResult(res) => {
				error!(
					logger, "unexpected authentication result";
					"auth_result" => format!("{:?}", res),
				)
			}
			AuthErrorReason::SshError(e) => error!(
				logger, "error occurred during authentication";
				"error" => format!("{:?}", e),
			),
			AuthErrorReason::Denied => error!(
				logger, "authentication failed as all provided credentials has been denied";
			),
			AuthErrorReason::LoadKeyFailed => error!(logger, "failed to load the key file"),
			AuthErrorReason::ReadPasswordFailed(e) => error!(
				logger, "error occurred when reading password";
				"error" => format!("{:?}", e),
			)
		}
		false
	} else {
		true
	}
}
