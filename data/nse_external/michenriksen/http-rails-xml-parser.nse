description = [[
Checks to see if a web server is running a Ruby on Rails application that is vulnerable to the CVE-2013-0156 bug.

The script sends a specially crafted XML body in a POST request that triggers the XML parser into attempting to parse invalid YAML and should result
in a `500 Internal Server Error` from the application.

If an application is vulnerable, it is possible to execute arbitrary Ruby code, perform SQL Injection under certain conditions and Denial of Service.
See https://community.rapid7.com/community/metasploit/blog/2013/01/10/exploiting-ruby-on-rails-with-metasploit-cve-2013-0156 for more details.
]]

---
-- @usage
-- nmap -sV --script http-rails-xml-parser <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | Looks like a Rails server with vulnerable XML parser (CVE-2013-0156)
-- | See http://bit.ly/13uq8Uk for exploitation details
--
-- @args http-rails-xml-parser.uri URI used in POST request. Default: /

author     = "Michael Henriksen"
license    = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln"}

local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local openssl   = stdnse.silent_require "openssl"

portrule = shortport.http

local DEFAULT_URI  = "/"
local HTTP_OPTIONS = {
  ['header'] = {
    ['Content-Type'] = 'application/xml'
  }
}

probe = function(host, port, uri, data)
  local response = http.post(host, port, uri, HTTP_OPTIONS, nil, data)
  return response.status
end

action = function(host, port)
  local output   = {}
  local uri      = stdnse.get_script_args("http-rails-xml-parser.uri") or DEFAULT_URI
  stdnse.print_debug(1, "URI: %s", uri)

  local probe_normal_xml   = probe(host, port, uri, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<probe type=\"string\"><![CDATA[\nhello\n]]></probe>")
  local probe_valid_yaml   = probe(host, port, uri, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<probe type=\"yaml\"><![CDATA[\n--- !ruby/object:Time {}\n\n]]></probe>")
  local probe_invalid_yaml = probe(host, port, uri, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<probe type=\"yaml\"><![CDATA[\n--- !ruby/object:\0\n]]></probe>")

  stdnse.print_debug(1, "Response with normal XML   :  %i", probe_normal_xml)
  stdnse.print_debug(1, "Response with valid YAML   :  %i", probe_valid_yaml)
  stdnse.print_debug(1, "Response with invalid YAML :  %i", probe_invalid_yaml)

  if probe_invalid_yaml ~= probe_normal_xml and probe_invalid_yaml ~= probe_valid_yaml and probe_invalid_yaml == 500 then
    output[#output+1] = "Looks like a Rails server with vulnerable XML parser (CVE-2013-0156)"
    output[#output+1] = "See http://bit.ly/13uq8Uk for exploitation details"
  else
    stdnse.print_debug(1, "Host does not seem to have a vulnerable XML parser")
  end

  if #output > 0 then
    return stdnse.strjoin("\n", output)
  end
end