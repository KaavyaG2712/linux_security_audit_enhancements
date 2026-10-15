description = [[
Local static review of selected SSH daemon settings in /etc/ssh/sshd_config.
Run only against localhost. Does not resolve Include files or Match blocks,
so findings should be verified against the effective sshd configuration.
This is a custom demonstration script, not an official Lynis script.
]]
author = "Student project"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.ip == "127.0.0.1" or host.ip == "::1"
end

local function read_settings(path)
  local f = io.open(path, "r")
  if not f then return nil, "Cannot read " .. path end
  local settings = {}
  for line in f:lines() do
    line = line:gsub("#.*$", "")
    local key, value = line:match("^%s*(%S+)%s+(%S+)")
    if key and value then
      key = key:lower()
      if key == "permitrootlogin" or key == "passwordauthentication" then
        settings[key] = value:lower()
      end
    end
  end
  f:close()
  return settings
end

action = function(host)
  local path = "/etc/ssh/sshd_config"
  local settings, err = read_settings(path)
  if not settings then return "[WARNING] " .. err end

  local out = {"Enhanced SSH Configuration Audit", "Source: " .. path}

  if not settings.permitrootlogin then
    table.insert(out, "[INFO] PermitRootLogin not found in this file; verify effective sshd configuration")
  elseif settings.permitrootlogin == "no" then
    table.insert(out, "[PASS] PermitRootLogin is set to no")
  else
    table.insert(out, "[WARNING] PermitRootLogin is set to " .. settings.permitrootlogin ..
      "; review whether root SSH login is required")
  end

  if not settings.passwordauthentication then
    table.insert(out, "[INFO] PasswordAuthentication not found in this file; verify effective sshd configuration")
  elseif settings.passwordauthentication == "no" then
    table.insert(out, "[PASS] PasswordAuthentication is set to no")
  else
    table.insert(out, "[INFO] PasswordAuthentication is set to " .. settings.passwordauthentication ..
      "; confirm this matches the intended authentication policy")
  end

  table.insert(out, "[INFO] Limitation: this static check does not resolve Include files or Match blocks.")
  table.insert(out, "[INFO] Verify effective settings with: sudo sshd -T")
  return table.concat(out, "\n")
end
