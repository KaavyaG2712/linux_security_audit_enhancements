description = [[
Baseline local Linux configuration file availability check.
Restricted to IPv4 and IPv6 loopback targets.
]]
author = "Kaavya Gupta"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.ip == "127.0.0.1" or host.ip == "::1"
end

action = function(host)
  local paths = {
    "/etc/login.defs",
    "/etc/ssh/sshd_config"
  }
  local out = {"Baseline Linux Configuration Audit", "Target: localhost"}
  for _, path in ipairs(paths) do
    local f = io.open(path, "r")
    if f then
      f:close()
      table.insert(out, "[INFO] Found configuration file: " .. path)
    else
      table.insert(out, "[WARNING] Could not read configuration file: " .. path)
    end
  end
  return table.concat(out, "\n")
end
