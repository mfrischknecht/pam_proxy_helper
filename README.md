# `pam_proxy_helper`

`pam_proxy_helper` is a helper binary for PAM authentication setups
intended to be used through [`pam_exec.so`](https://manpages.debian.org/stable/libpam-modules/pam_exec.8.en.html).
The helper is useful as a separated privilege escalation step for pam policies
that require elevated rights to be checked. In some cases, it's not desirable
to give the necessary privileges to a service that accepts external
connections and relies on PAM policies to authenticate client connections.


## Motivation

As an example, consider an NGINX server that is configured to check
clients against its system's `/etc/passwd` and `/etc/shadow`. In order to
authenticate inbound client connections, NGINX would have to rely on
a `pam_unix.so` policy to check the provided user's password.
`pam_unix.so` uses a dedicated helper binary (`unix_chkpwd`) to validate
these client requests, and `pam_unix.so` _always_ executes after acquiring
root privileges through `setuid(0)` as of the time of writing [^1].
And since the helper binary must be able to read `/etc/shadow` in order
to verify a client's password, even changing that fact would only go so
far, as far as the privilege requirements for performing these auth checks go.

[^1]: https://github.com/linux-pam/linux-pam/blob/e634a3a9be9484ada6e93970dfaf0f055ca17332/modules/pam_unix/support.c#L568

This means that effective hardening of the NGINX service in question will
effectively prevent it from performing any such auth checks against the local
*NIX password database. And on the flip side, if the service _must_ be able to
perform these checks, it _must_ have system privileges that are risky to expose
to remote clients. If the NGINX service were to be compromised through e.g. a
memory safety issue, attacking clients could essentially instantly gain `root`
access to the entire machine without having to deal with any further mitigations
(since the code for `pam_unix.so` runs directly in the calling service).

In order to avoid this, it is instead possible to perform said authentication
checks through a "proxy" PAM policy that calls `pam_proxy_helper` through
`pam_exec.so`. If the `pam_proxy_helper` binary is installed with the `setuid`
and `setgid` bits set [^3], the binary will automatically gain the necessary
rights to then call `pam_unix.so` _without_ the calling service (i.e. NGINX)
having the same access rights, too. `pam_proxy_helper` will then run the check
on the "real" PAM policy and simply signal its success or failure. This reduced
minimizes the attack surface of this scenario considerably.

Note that in scenario where one is aggressively limiting the privileges of a
service (e.g. through systemd policies), there still are some concessions
necessary: In the example of NGINX, the service still needs `CAP_SETUID`
in `CapabilityBoundingSet` (note: not in `AmbientCapabilities`, though),
the `setuid`, `setgid` and `capset` system calls must not be blocked (via
`SystemCallFilter`) and `NoNewPrivileges` must be set to `false`. See the
[`systemd.exec` manpage](https://manpages.debian.org/stable/systemd/systemd.exec.5.en.html)
for further details on these settings.

[^3]: https://manpages.debian.org/stable/coreutils/chmod.1.en.html#SETUID_AND_SETGID_BITS


## Usage

As an example, in order to set up a `pam_proxy_helper` policy with a
`pam_unix.so` backend for the NGINX example above, one has to set up
_two_ policies. The first one, directly used by NGINX, only calls the
`pam_proxy_helper` binary in order to perform the mentioned auth check:


```
# cat <<'EOF' > /etc/pam.d/nginx_proxy
auth required pam_exec.so expose_authtok /usr/sbin/pam_proxy_helper nginx_target
account required pam_permit.so
session required pam_permit.so
EOF
```

The second policy, in turn, will be used by `pam_proxy_helper` to
perform the _actual_ auth checks through `pam_unix.so`:

```
# cat <<'EOF' > /etc/pam.d/nginx_target
auth required pam_unix.so
account required pam_unix.so
session required pam_permit.so
EOF
```

The first (`nginx_proxy`) policy can then be used in the NGINX config to
authenticate client requests for virtual hosts via [`ngx_http_auth_pam_module`](https://github.com/sto/ngx_http_auth_pam_module?tab=readme-ov-file#examples):

```
auth_pam  "Restricted";
auth_pam_service_name "nginx_proxy";
```

As explained above, this setup requires that `pam_proxy_helper`
has been installed on the system with its `setuid(root)` and
`setgid(shadow)` bits set:

```
# chown root:shadow /usr/sbin/pam_proxy_helper
# chmod u+s /usr/sbin/pam_proxy_helper
# chmod u+g /usr/sbin/pam_proxy_helper
```