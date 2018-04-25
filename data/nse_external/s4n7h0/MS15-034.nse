local http = require "http"
local shortport = require "shortport"

description = [[
HTTP.sys Denial of Service(BSoD). This script will check if scanned hosts are vulnerable to CVE-2015-1635 / MS15-034. 
This script will not cause BSoD. If the hosts are found to be vulnerable, sending request with Range: bytes=18-18446744073709551615 may cause BSoD. 

https://technet.microsoft.com/en-us/library/security/ms15-034.aspx 
]]

---
-- @usage
--
-- nmap --script MS15-034 --script-args="MS15-034.uri=/iisstart.htm" <ip>
--
-- @args MS15-034.uri       [default : /iisstart.htm]
--
--
--@output
--80/tcp open  http    syn-ack
--|_MS15-034: host is vulnerable to MS15-034
---

author = "Sanoop Thomas"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local uri = ""
  local payload = {
    header = {
      Host = host.ip,
      Range = "bytes=0-18446744073709551615"
    }
  }

  if(nmap.registry.args.uri) then 
    uri = tostring(nmap.registry.args.uri) 
  else
    uri = "/iisstart.htm"
  end

  print(uri)
  local resp = http.get(host, port, uri, payload)

  for k,v in pairs(resp.rawheader) do
    if v:match("IIS") then
	if resp["status-line"]:match("Requested Range Not Satisfiable") and resp.status == 416 then
          return "host is vulnerable to MS15-034"
        else
          return "host is not vulnerable to MS15-034"
        end
    end
  end
  return "nothing"
end
