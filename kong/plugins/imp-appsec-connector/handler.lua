--[[
--:module:: handler.lua
--:platform: Linux
--:synopsis: An interface to implement. Each function is to be run by Kong at the desired moment in the lifecycle of a request.
--:copyright: (c) 2022 Imperva Inc. All rights reserved. (This is modified based on tcp-log plugin provided by Kong)
--:moduleauthor: Sekhar <contact@arecabay.com> (Nov 19, 2022)
--]]--

local fmt = string.format
local http = require "resty.http"
local url = require "socket.url"
local socket = require("socket")

local ApiExporterHandler = {
    PRIORITY = 799,
    VERSION = "2.0.0",
    }


local destination_ip  = "0.0.0.0"

local resp_body 
local client_ip

local parsed_urls_cache = {}
local headers_cache = {}
local response_headers = {}
local params_cache = {
	ssl_verify = false, 
	headers = headers_cache,
}

local response_params_cache = {
	ssl_verify = false, 
	headers = response_headers,
}

-- local unique_id = math.random(100000, 999999)
uniq_id = math.random(100000, 999999)

local function parse_url(host_url)
  local parsed_url = parsed_urls_cache[host_url]

  if parsed_url then
    return parsed_url
  end

  kong.log.err('url old', host_url)
  parsed_url = url.parse(host_url)
  --kong.log.err('url', parsed_url, host_url)
  if not parsed_url.port then
    if parsed_url.scheme == "http" then
      parsed_url.port = 80
    elseif parsed_url.scheme == "https" then
      parsed_url.port = 443
    end
  end
  if not parsed_url.path then
    parsed_url.path = "/"
  end

  parsed_urls_cache[host_url] = parsed_url

  return parsed_url
end


local function compose_payload(constant_string, header, payload)
	local output_log = constant_string
	header["transfer-encoding"] = nil
	for k, v in pairs(header) do
		if  type(v) == 'table' then
			local new_string
			for key, value in pairs(v) do
				if not new_string then 
					new_string = value 
				else 
					new_string = fmt("%s, %s", new_string, value)
				end
			end
			output_log =  fmt("%s%s:%s\n", output_log, k, new_string)
		else
			output_log =  fmt("%s%s:%s\n", output_log, k, v)
		end
	end

	if payload then
		output_log = fmt("%s\r\n%s\n", output_log, payload)
	end
	
	output_log = fmt("%s<CVLOG907A3>\n", output_log)
	return output_log
end


local function create_connection(conf, destination_addr)
	local parsed_url = parse_url(destination_addr)
  	local host = parsed_url.host
 	local port = tonumber(parsed_url.port)

  	local url = fmt("%s://%s:%d%s", parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path)
  	if parsed_url.query then
    		url = url .. "?" .. parsed_url.queryend
	end

	local connection = conf.connection_type
	local ssl_verify = conf.ssl


	kong.log.err("host, post", host, port)
	local conn 
	if string.lower(connection) == "tcp" then
		conn = socket.tcp()
		local ok, err = conn:connect(host, port)

		kong.log.err("check connection", conn, ok)
	elseif string.lower(connection) == "http" then
		conn = http.new()

	end

	local params = {
		mode = "client",
		certificate = "/home/ubuntu/github_dir/platform/bld/conf/cert/ABRootCert.pem",
		options = "all",
		verify = "none",
		protocol = "any"
	}
	local ssl = require("ssl")
	if ssl_verify then
		kong.log.err("ssl verify")
		conn = ssl.wrap(conn, params)
	end

	--local sock = ngx.socket.tcp()
	--ok, err = sock:connect(host, port)
	--ok, err = sock:send(payload)


	--local httpc = http.new()
	--local res, err = conn:request_uri(url, params_cache)

	--kong.log.err("request handshake ", lfs.currentdir())

	--local cert_file = lfs.currentdir() .. "/ABDevRootCert.pem"
	---kong.log.err("dir", cert_file)

	--kong.log.err("connection", ok, err, params)
	--conn = ssl.wrap(conn, params)
	--kong.log.err("ssl wrap", conn)
	--conn:dohandshake()
	--kong.log.err("request handshake ", conn)
	
	return conn

end


local function send_request_payload(conf, uniq_id)
	local method = conf.method
  	local destination_addr = conf.destination_addr

	local payload = kong.request.get_raw_body()
	local header, err = ngx.req.get_headers()
	local destination_ip = kong.request.get_host()
	local unique_id = uniq_id
	local request_string = fmt("<CVLOG907A3>|CV_LOG_1|kong|%s|request|%s000|0|%s|%s|", unique_id, os.time(os.date("!*t")), client_ip, destination_ip)
	local constant_string = fmt("%s\n%s %s HTTP/1.1\r\n", request_string,kong.request.get_method(), kong.request.get_path())
	payload = compose_payload(constant_string, header, payload)

	headers_cache["Content-Type"] = "text/plain"
  	
	params_cache.method = method
  	params_cache.body = payload

	kong.log.err("request payload", payload)
	local conn = create_connection(conf, destination_addr)
	local ok, err = conn:send(payload)
	--local line, err = conn:receive()
	conn:close()

end

function send_response_payload(conf, resp_body, uniq_id)
	local method = conf.method
  	local destination_addr = conf.destination_addr
	local unique_id = uniq_id

	local response_header = kong.response.get_headers()
	--local resp_body = kong.response.get_raw_body()
	local destination_ip = kong.request.get_host()
	local response_status = kong.response.get_status()

	local latency = 0
	for k, v in pairs(response_header) do
		if k == 'x-kong-proxy-latency' then
			latency = v
		end
	end

	local response_string = fmt("<CVLOG907A3>|CV_LOG_1|kong|%s|response|%s000|%s|%s|%s|", unique_id, os.time(os.date("!*t")), latency, client_ip, destination_ip)
	local constant_string = fmt("%s\nHTTP/1.1 %s Created\r\n",response_string, response_status)
	local response_payload = compose_payload(constant_string, response_header, resp_body)


	response_headers["Content-Type"] = "text/plain"

	response_params_cache.method = conf.method
	response_params_cache.body = response_payload
	
	kong.log.err("response payload", response_payload)
	
	local conn = create_connection(conf, destination_addr)
	--kong.log.err("response conn", conn)
	local ok, err = conn:send(response_payload)
	--local line, err = conn:receive()
	conn:close()

end

function ApiExporterHandler:access(conf) 

	uniq_id = math.random(100000, 999999)
	client_ip = kong.client.get_ip()
	send_request_payload(conf, uniq_id)

end

function ApiExporterHandler:body_filter(conf)
	resp_body = kong.response.get_raw_body()
--	send_response_payload(conf, resp_body)
end

function ApiExporterHandler:log(conf)
	send_response_payload(conf, resp_body, uniq_id)
end
	


return ApiExporterHandler

