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
	ReadPasswordFailed(std::io::Error),
}

#[derive(Debug)]
struct AuthError {
	reason: AuthErrorReason,
	auth_list: SshAuthMethod,
}

extern fn get_passphrase(prompt: &str) -> Option<String> {
	rpassword::prompt_password_stdout(prompt).ok()
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
				let mut state = AuthState::Denied;
				for key_file in key_files {
					let logger = logger.new(o!("key_file" => (*key_file).to_owned()));
					debug!(logger, "trying public key authentication");
					if let Some(key) = SshKey::from_private_key_file(key_file, get_passphrase) {
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
				match state {
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

		if auth_list.contains(SshAuthMethod::PASSWORD) {
			debug!(logger, "trying password authentication");
			let password = rpassword::prompt_password_stdout("Password: ")
				.map_err(|e| AuthError { reason: AuthErrorReason::ReadPasswordFailed(e), auth_list })?;
			match check_auth_result(session, session.auth_password(&password), auth_list)? {
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
