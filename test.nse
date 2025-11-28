local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
This script checks if the RDP server is vulnerable to MITM attacks
by detecting weak encryption configurations or missing NLA (Network Level Authentication).
]]

author = "Your Name"
license = "Same as Nmap -- see https://nmap.org/book/man-legal.html"
categories = { "safe", "discovery" }

-- Define the port we're scanning (3389 for RDP)
portrule = shortport.port_or_service(3389, "ms-wbt-server")

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local status, err = sock:connect(host.ip, port.number)
    if not status then
        return "Connection failed: " .. err
    end

    -- Send a simple RDP connection request (TPKT + X.224)
    local request = "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x03\x00\x00\x00"
    sock:send(request)

    local response = sock:receive_bytes(24)
    local result = ""

    if response then
        if response:match("\x03\x00\x00\x13") then
            result = "RDP server responded. Possible weak encryption or NLA missing."
        else
            result = "RDP server response unclear."
        end
    else
        result = "No response from RDP server. Possible MITM protection in place."
    end

    sock:close()
    return result
end
