use std::io::Read;
use std::path::PathBuf;

use pam_client::conv_mock::Conversation;
use pam_client::{Context, Flag};

fn print_usage() -> ! {
    let executable_path = find_executable_path();
    let executable_path = executable_path.to_string_lossy();

    #[rustfmt::skip]
    eprintln!("
PAM exec proxy helper

This helper binary is meant to use as the target
binary for a `pam_exec` rule so that PAM services
that would otherwise require setuid rights and
access to /etc/shadow can be used by more
restricted services instead.

As an example, checks that use `pam_unix` are performed
via a dedicated `unix_chkpwd` helper binary that must
be run as root, i.e. the process that performs the
authentication also must have the rights to attain
root privileges.

In order to avoid this, this helper can instead be used
through a \"proxy PAM service\" via `pam_exec`; if the
`pam_proxy_helper` binary has been annotated as e.g.
setuid root and setgid shadow, the binary will
automatically attain root privileges without any
related `setuid()` and `setgid()` syscalls in the
calling service:

```
# chown root:shadow ./pam_proxy_helper
# chmod u+s ./pam_proxy_helper
# chmod u+g ./pam_proxy_helper
```

Since the helper binary only ever performs a PAM
authentication check and runs no further logic, this
is likely a better security tradeoff than giving an
externally visible service (e.g. NGINX) the rights
to perform `setuid(0)` or read from /etc/shadow.

By configuring two PAM services instead of one
in /etc/pam.d, we can then make use of this utility:

```
# cat <<'EOF' > /etc/pam.d/nginx_proxy
auth required pam_exec.so expose_authtok {executable_path} nginx_target
account required pam_permit.so
session required pam_permit.so
EOF

# cat <<'EOF' > /etc/pam.d/nginx_target
auth required pam_unix.so
account required pam_unix.so
session required pam_permit.so
EOF
```");

    //If this executable is registered without any arguments or with `--help` in /etc/pam.d,
    //we don't want it to return `PAM_SUCCESS` (0) as its exit code, as that would cause PAM
    //to accept an authentication request. So, printing this message should still be an "error"
    //from the view of the program's intended usage scenario.
    std::process::exit(pam_client::ErrorCode::SYSTEM_ERR as i32);
}

struct AuthenticationParameters {
    pam_service_name: String,
    username: String,
    auth_token: String,
}

fn main() {
    let parameters = gather_pam_parameters();
    let user = &parameters.username;

    let conversation = Conversation::with_credentials(&parameters.username, &parameters.auth_token);
    let mut context = match Context::new(&parameters.pam_service_name, None, conversation) {
        Ok(context) => context,
        Err(e) => {
            eprintln!("Failed to initialize PAM client context: {e}");
            std::process::exit(pam_client::ErrorCode::SYSTEM_ERR as i32);
        }
    };

    if let Err(e) = context.authenticate(Flag::NONE) {
        eprintln!("Failed to authenticate user '{}': {e}", parameters.username);
        std::process::exit(e.code() as i32);
    }

    if let Err(e) = context.acct_mgmt(Flag::NONE) {
        eprintln!("Successfully authenticated user '{user}', but the account is invalid: {e}");
        std::process::exit(e.code() as i32);
    }

    println!("Successfully authenticated user '{user}'");
}

fn gather_pam_parameters() -> AuthenticationParameters {
    let mut arguments = std::env::args();

    //"Argument 1" is the executed binary, so this means there are no arguments:
    if arguments.len() <= 1 {
        print_usage();
    }

    if arguments.len() != 2 {
        fail_on_invalid_invocation("Invalid command line arguments");
    }

    let pam_service_name = arguments.nth(1).unwrap();
    if ["--help", "-h"].contains(&pam_service_name.as_str()) {
        print_usage();
    }

    // Make sure we're in a `pam_exec` environment for an authentication request
    // See: https://manpages.debian.org/stable/libpam-modules/pam_exec.8.en.html
    let Ok(pam_type) = std::env::var("PAM_TYPE") else {
        fail_on_invalid_invocation("`PAM_TYPE` is not set");
    };

    if pam_type != "auth" {
        fail_on_invalid_invocation(&format!("`PAM_TYPE` '{pam_type}' is not supported"));
    }

    let parent_pam_service = std::env::var("PAM_SERVICE").unwrap_or_else(|_| "".into());
    if parent_pam_service == pam_service_name {
        eprintln!("Invoking pam service '{pam_service_name}' while being called from '{parent_pam_service}' would cause an infinite recursion");
        std::process::exit(pam_client::ErrorCode::SYSTEM_ERR as i32);
    }

    let Ok(username) = std::env::var("PAM_USER") else {
        fail_on_invalid_invocation("Username not provided via `PAM_USER`");
    };

    let auth_token = read_auth_token_from_stdin();

    AuthenticationParameters {
        pam_service_name,
        username,
        auth_token,
    }
}

fn read_auth_token_from_stdin() -> String {
    //Since we have to read them into memory, we shouldn't accept arbitrarily large
    //authorization tokens (i.e. passwords, mostly). While passwords should never get
    //too large anyway (meaning we could use a much lower maximum size threshold),
    //PAM also supports other authentication methods like e.g. Kerberos (see: pam_krb5),
    //for which the tokens might be considerably larger.
    const MAX_AUTHTOK_SIZE: u64 = 4 << 20; //4 MiB

    let mut auth_token = String::new();

    match std::io::stdin()
        .take(MAX_AUTHTOK_SIZE + 1)
        .read_to_string(&mut auth_token)
    {
        Ok(size) if size as u64 <= MAX_AUTHTOK_SIZE => (),
        Ok(_) => {
            eprintln!("Supplied auth token is too large");
            std::process::exit(pam_client::ErrorCode::SERVICE_ERR as i32);
        }
        Err(e) => {
            eprintln!("Failed to read auth token from stdin: {e:?}");
            std::process::exit(pam_client::ErrorCode::SERVICE_ERR as i32);
        }
    }

    auth_token
}

fn find_executable_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| "/path/to/pam_proxy_helper".into())
}

fn fail_on_invalid_invocation(message: &str) -> ! {
    let executable_path = find_executable_path();
    let executable = executable_path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_else(|| "pam_proxy_helper".into());

    eprintln!("{message}");
    eprintln!("This program should be used via `pam_exec`");
    eprintln!("Run `{executable} --help` for a detailed explanation how to it up");
    std::process::exit(pam_client::ErrorCode::SYSTEM_ERR as i32);
}
