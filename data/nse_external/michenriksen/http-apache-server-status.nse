description = [[
Checks if a web server is serving the Apache Server Status page which can contain a lot of interesting
information such as Apache version, CPU usage, uptime and the latest requests.

Daniel Cid did some research and found sites such as php.net, cloudfare.com, disney.com, ford.com and cisco.com
having the /server-status page wide open to the public.

Read more about his findings here: http://blog.sucuri.net/2012/10/popular-sites-with-apache-server-status-enabled.html

To see how a server status page looks: http://www.apache.org/server-status
]]

---
-- @usage
-- nmap -sV --script http-apache-server-status <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | Apache Server Status page is available and might contain juicy info. (/server-status)

author     = "Michael Henriksen"
license    = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local openssl   = stdnse.silent_require "openssl"

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/server-status")

  if response.status == 200 and string.match(response.body, "<title>Apache Status</title>") then
    return "Apache Server Status page is available and might contain juicy info. (/server-status)"
  else
    stdnse.print_debug(1, "GET /server-status returned " .. response['status-line'])
  end
end