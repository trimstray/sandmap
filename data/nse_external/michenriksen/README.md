# Nmap NSE Scripts

**A collection of [Nmap NSE scripts](http://nmap.org/nsedoc/) that I made.**

## Scripts:

### http-rails-xml-parser
This script sends a specially crafted XML body in a POST request to any detected web services to see if it is a Ruby on Rails server
that is vulnerable to the recently discovered [CVE-2013-0156](https://groups.google.com/forum/#!topic/rubyonrails-security/61bkgvnSGTQ/discussion) bug.

**Usage:**

    $ nmap -sV --script http-rails-xml-parser <target>

----

### http-apache-server-status
This script checks if a web server is serving the Apache Server Status page which might contain a lot of interesting information. Daniel Cid did some
research and found big sites having the server-status page wide open to the public. [Read more about it here](http://blog.sucuri.net/2012/10/popular-sites-with-apache-server-status-enabled.html).

**Usage:**

    $ nmap -sV --script http-apache-server-status <target>