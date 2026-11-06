# Local Linux Configuration Auditing with Nmap NSE

Independent educational project using three custom Lua-based Nmap Scripting Engine scripts for local Linux configuration checks.

## Scripts
- `reference_linux_config_audit.nse`: checks availability of `/etc/login.defs` and `/etc/ssh/sshd_config`.
- `enhanced_password_policy_audit.nse`: reads `PASS_MAX_DAYS` and `PASS_MIN_DAYS` in `/etc/login.defs`.
- `enhanced_ssh_config_audit.nse`: statically reviews `PermitRootLogin` and `PasswordAuthentication` in `/etc/ssh/sshd_config`.

## Test environment
Linux Mint virtual machine, Nmap 7.94SVN, target `127.0.0.1`. The tested machine did not contain `/etc/ssh/sshd_config`; the SSH run therefore could not establish effective SSH authentication settings. The password-aging run observed `PASS_MAX_DAYS = 99999` and `PASS_MIN_DAYS = 0`.

## Scope and limitations
These scripts use local file access and are restricted to loopback targets. They inspect the machine running Nmap; they do not remotely read files from other hosts. The baseline check confirms file availability only. The password script reads system-wide defaults, not individual account aging. The SSH parser does not resolve `Include` files or conditional `Match` blocks. This is an educational project, not a comprehensive security audit or part of the official Nmap script distribution.

## Run
```bash
sudo nmap --script ./reference_linux_config_audit.nse -oN reference_output.txt 127.0.0.1
sudo nmap --script ./enhanced_password_policy_audit.nse -oN password_policy_output.txt 127.0.0.1
sudo nmap --script ./enhanced_ssh_config_audit.nse -oN ssh_config_output.txt 127.0.0.1
```

Repository: https://github.com/KaavyaG2712/linux_security_audit_enhancements
