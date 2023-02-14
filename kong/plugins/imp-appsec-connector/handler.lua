--[[
--:module:: handler.lua
--:platform: Linux
--:synopsis: An interface to implement. Each function is to be run by Kong at the desired moment in the lifecycle of a request.
--:copyright: (c) 2022 Imperva Inc. All rights reserved. (This is modified based on tcp-log plugin provided by Kong)
--:moduleauthor: Nainika <nainika.aggarwal@imperva.com> (Nov 19, 2022)
--]]--

local fmt = string.format
local http = require "resty.http"
local url = require "socket.url"
local socket = require("socket")

local ApiExporterHandler = {
    PRIORITY = 799,
    VERSION = "2.0.0",
    }


local response_status_string = {
	["200"] = "OK",
	['201'] =  'CREATED',
	['202'] = 'Accepted',
	['203'] = 'Partial Information',
	['304'] = 'Not Modified',
	['401'] = 'Unauthorized',
	['403'] = 'Forbidden'
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
local responsestr = "{\"message\": \"Response size limit exceeded\"}"

uniq_id = math.random(100000, 999999)

local function parse_url(host_url)
  local parsed_url = parsed_urls_cache[host_url]

  if parsed_url then
    return parsed_url
  end

  kong.log.err('url old', host_url)
  parsed_url = url.parse(host_url)
  kong.log.err('url', parsed_url, host_url)
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

	kong.log.err("destination add", destination_addr)
	local parsed_url = parse_url(destination_addr)
  	local host = parsed_url.host
 	local port = tonumber(parsed_url.port)

	local connection = conf.connection_type
	local ssl_verify = conf.ssl
	
	local port = conf.destination_port
	local host = conf.destination_addr

	kong.log.err("host, post", host, port)
	local conn 
	conn = socket.tcp()
	local ok, err = conn:connect(host, port)

	kong.log.err("check connection", conn, ok)

	local params = {
		mode = "client",
		protocol = "any",
		options = "all",
		verify = "none",
		certificate = "/home/ubuntu/github_dir/platform/bld/conf/cert/ABDevRootCert.pem",
	}
	local ssl = require("ssl")
	if ssl_verify then
		kong.log.err("ssl verify")
		conn = ssl.wrap(conn, params)
		conn:dohandshake()
		kong.log.err("ssl conn", conn)
	end

	return conn, host

end

local function send_request_payload(premature, conf, payload, header, destination_ip, method, path, uniq_id)
	local method = conf.method
  	local destination_addr = conf.destination_addr
	
	local host = "/api/v1/CV_LOG_1"
	local unique_id = uniq_id
	local request_string = fmt("<CVLOG907A3>|CV_LOG_1|kong|%s|request|%s000|0|%s|%s|", unique_id, os.time(os.date("!*t")), client_ip, destination_ip)
	local constant_string = fmt("%s\n%s %s HTTP/1.1\r\n", request_string, method, path)
	payload = compose_payload(constant_string, header, payload)


	local conn, host = create_connection(conf, destination_addr)
	local message2 = "POST /api/v1/CV_LOG_1" .. " HTTP/1.1\r\nHost: " .. host .. "\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\nContent-Length: " .. string.len(payload) .. "\r\n\r\n" .. payload
	   
	if conf.connection_type == "http" then
		payload = message2
	end


	kong.log.err("request payload", payload)
	local ok, err = conn:send(payload)
	conn:close()

end

function send_response_payload(premature, conf, resp_body, response_header, destination_ip, response_status, uniq_id)
	local method = conf.method
  	local destination_addr = conf.destination_addr
	local unique_id = uniq_id

	local host = "/api/v1/CV_LOG_1"
	local latency = 0
	for k, v in pairs(response_header) do
		if k == 'x-kong-proxy-latency' then
			latency = v
		end
	end

	local response_string = fmt("<CVLOG907A3>|CV_LOG_1|kong|%s|response|%s000|%s|%s|%s|", unique_id, os.time(os.date("!*t")), latency, client_ip, destination_ip)
	local constant_string = fmt("%s\nHTTP/1.1 %s %s\r\n",response_string, response_status, response_status_string[tostring(response_status)])
	local response_payload = compose_payload(constant_string, response_header, resp_body)


	local conn, host = create_connection(conf, destination_addr)
	local message2 = "POST /api/v1/CV_LOG_1"  .. " HTTP/1.1\r\nHost: " .. host .. "\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\nContent-Length: " .. string.len(response_payload) .. "\r\n\r\n" .. response_payload
	   
	if conf.connection_type == "http" then
		response_payload = message2
	end

	local ok, err = conn:send(response_payload)
	conn:close()

end

function ApiExporterHandler:access(conf) 

	uniq_id = math.random(100000, 999999)
	client_ip = kong.client.get_ip()
	local payload = kong.request.get_raw_body()
	local header, err = ngx.req.get_headers()
	local destination_ip = kong.request.get_host()
	local method = kong.request.get_method()
	path = kong.request.get_path()
	local premature
	local ok, err = ngx.timer.at(0, send_request_payload, conf, payload, header, destination_ip, method, path,  uniq_id)

end


function ApiExporterHandler:header_filter(conf)
	
	local cl = ngx.var.upstream_http_content_length
	kong.log.err("length, cl", tonumber(cl))
	
end

function ApiExporterHandler:body_filter(conf)
	resp_body = kong.response.get_raw_body()
end

function ApiExporterHandler:log(conf)
	local response_header = kong.response.get_headers()
	local destination_ip = kong.request.get_host()
	local response_status = kong.response.get_status()
	
	local MB = 2^20
	local resp_body_len = #resp_body
	local responsestr = "{\"message\": \"Response size limit exceeded\", \"size\":" .. resp_body_len .. "}" 
	kong.log.err("len", resp_body_len, "hhhhhh", MB)
	if resp_body_len > MB then
		
		response_header['content-encoding'] = nil
		resp_body =  responsestr
	end
	
	local premature
	local ok, err = ngx.timer.at(0, send_response_payload, conf, resp_body, response_header, destination_ip, response_status, uniq_id)
end
	
return ApiExporterHandler

