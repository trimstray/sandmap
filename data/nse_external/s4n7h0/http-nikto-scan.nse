description = [[ "This script will run nikto on web servers found" ]] 
author = {"Sanoop Thomas a.k.a. @s4n7h0"} 
category = {"safe","discovery","vuln"}

---
-- @usage
--
-- nmap --script http-nikto-scan <ip>
--
-- @args http-nikto-scan.display		shows nikto scan result in nmap scan, takes values "on" or "off". [default : "off"]
---
--PORT     STATE SERVICE      REASON
--80/tcp   open  http         syn-ack
--| http-nikto-scan: 
--|_  nikto scan result saved to http-nikto-scan-172.16.100.129:80.html
--8080/tcp open  http-proxy   syn-ack
--| http-nikto-scan: 
--|_  nikto scan result saved to http-nikto-scan-172.16.100.129:8080.html
---

local shortport = require('shortport')
local stdnse = require('stdnse')

portrule = shortport.http

action = function(host,port)
	
	local result 
	local filename = "http-nikto-scan-" .. host.ip .. ":" .. port.number .. ".html"
	local cmd = "nikto -host " .. host.ip .. " -port " .. port.number .. " -Format html -output " .. filename .. "> /dev/null"
	if(nmap.registry.args.display == "on") then
		local cmd = "nikto -host " .. host.ip .. " -port " .. port.number .. " -Format html -output " .. filename
	end
	
	local ret = os.execute(cmd)
	if ret then
		result = "Nikto scan result saved to " .. filename
	end
	return stdnse.format_output(true, result)    
end
