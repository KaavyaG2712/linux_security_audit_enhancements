description = [[
Local password-aging policy review based on active PASS_MAX_DAYS and
PASS_MIN_DAYS entries in /etc/login.defs. Run only against localhost.
This is a custom demonstration script, not an official Lynis script.
]]
author = "Student project"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.ip == "127.0.0.1" or host.ip == "::1"
end

local function read_policy(path)
  local f = io.open(path, "r")
  if not f then return nil, "Cannot read " .. path end
  local values = {}
  for line in f:lines() do
    local key, value = line:match("^%s*(PASS_MAX_DAYS)%s+(%S+)")
    if not key then key, value = line:match("^%s*(PASS_MIN_DAYS)%s+(%S+)") end
    if key and value then values[key] = tonumber(value) end
  end
  f:close()
  return values
end

action = function(host)
  local path = "/etc/login.defs"
  local values, err = read_policy(path)
  if not values then return "[WARNING] " .. err end

  local out = {"Enhanced Password Policy Audit", "Source: " .. path}
  if values.PASS_MAX_DAYS == nil then
    table.insert(out, "[WARNING] PASS_MAX_DAYS not found or not numeric")
  elseif values.PASS_MAX_DAYS <= 0 then
    table.insert(out, "[WARNING] PASS_MAX_DAYS is not a positive expiry interval")
  elseif values.PASS_MAX_DAYS > 365 then
    table.insert(out, "[WARNING] PASS_MAX_DAYS is " .. values.PASS_MAX_DAYS ..
      " days; review whether this interval is appropriate")
  else
    table.insert(out, "[PASS] PASS_MAX_DAYS = " .. values.PASS_MAX_DAYS .. " days")
  end

  if values.PASS_MIN_DAYS == nil then
    table.insert(out, "[INFO] PASS_MIN_DAYS not found or not numeric")
  elseif values.PASS_MIN_DAYS < 0 then
    table.insert(out, "[WARNING] PASS_MIN_DAYS is negative")
  else
    table.insert(out, "[INFO] PASS_MIN_DAYS = " .. values.PASS_MIN_DAYS .. " days")
  end

  table.insert(out, "[INFO] Scope: reads /etc/login.defs only; does not audit existing user account aging.")
  return table.concat(out, "\n")
end
