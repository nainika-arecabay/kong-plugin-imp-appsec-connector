--[[
--:module:: handler.lua
--:platform: Linux
--:synopsis: An interface to implement. Each function is to be run by Kong at the desired moment in the lifecycle of a request.
--:copyright: (c) 2022 Imperva Inc. All rights reserved. (This is modified based on tcp-log plugin provided by Kong)
--:moduleauthor: Sekhar <contact@arecabay.com> (Nov 19, 2022)
--]]--

local kong_meta = require "kong.meta"
local fmt = string.format
local url = require "socket.url"
local http = require "resty.http"
local basic_serializer = require "kong.plugins.log-serializers.basic"
local JSON = require "kong.plugins.http-log-advanced.json"
local json = require("cjson")
local socket = require("socket")
--local uuid = require("uuid")

local ApiExporterHandler = {
    PRIORITY = 799,
    VERSION = "2.0.0",
    }


local resp_body = {};
local response_header = {}
local err = ""
local destination_ip  = "0.0.0.0"
local response_status

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


local function parse_url(host_url)
  local parsed_url = parsed_urls_cache[host_url]

  if parsed_url then
    return parsed_url
  end

  parsed_url = url.parse(host_url)
  if not parsed_url.port then
    if parsed_url.scheme == "http" then
      parsed_url.port = 80
    elseif parsed_url.scheme == "https" then
      parsed_url.port = 443
    end
  end
  kong.log.err("path", parsed_url.path)
  if not parsed_url.path then
    parsed_url.path = "/"
  end

  parsed_urls_cache[host_url] = parsed_url

  return parsed_url
end


--local function compose_payload(url, host, payload_json, message)
--  local payload = payload_json
  --payload['message'] = {message}
--  local payload_body = payload
--  local payload_headers = fmt(
--    "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\nContent-Length: %s\r\n",
--    url, host, #payload_body)

--  local res = fmt("%s\r\n%s\r\n%s", payload_headers, payload_body, resp_body)


  --kong.log.err("check string", res)
--  return res
--end

local function compose_payload(constant_string, header, payload)
	local output_log = constant_string
	header["transfer-encoding"] = nil
	for k, v in pairs(header) do
		--kong.log.err('new', k, v)
		if  type(v) == 'table' then
			local new_string
			for key, value in pairs(v) do
				--kong.log.err('new', key, value)
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


	--local payload = kong.request.get_raw_body()
	if payload then
		output_log = fmt("%s\r\n%s\n", output_log, payload)
	end
	
	output_log = fmt("%s<CVLOG907A3>\n", output_log)
	return output_log
end



local function get_log_format(conf)
	local method = conf.method
  	local timeout = conf.timeout
  	local keepalive = conf.keepalive
  	local content_type = conf.content_type
  	local http_endpoint = conf.http_endpoint

  	local parsed_url = parse_url(http_endpoint)
  	local host = parsed_url.host
 	local port = tonumber(parsed_url.port)


	local payload = kong.request.get_raw_body()

	local header, err = ngx.req.get_headers()

	local log_format_id = "CV_LOG_1"
	if  not resp_body then
		log_format_id = "CV_LOG_2"
	end

	kong.log.err("here's a new uuid: ", socket.gettime())
	local unique_id = math.random(100000, 999999)

	local request_string = fmt("<CVLOG907A3>|%s|kong|%s|request|%s000|0|%s|%s|", log_format_id, unique_id, os.time(os.date("!*t")), kong.client.get_ip(), destination_ip)
	local constant_string = fmt("%s\n%s %s HTTP/1.1\r\n", request_string,kong.request.get_method(), kong.request.get_path())
	payload = compose_payload(constant_string, header, payload)

  	headers_cache["Host"] = parsed_url.host
	headers_cache["Content-Type"] = "text/plain"
  	headers_cache["Content-Length"] = #payload
	
	kong.log.err("ip", kong.client.get_ip())

  	params_cache.method = method
  	params_cache.body = payload
  	--params_cache.keepalive_timeout = keepalive

  	local url = fmt("%s://%s:%d%s", parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path)

  	if parsed_url.query then
    		url = url .. "?" .. parsed_url.queryend
	end

	kong.log.err("here'sid: ",url, params_cache)

	--local message = basic_serializer.serialize(ngx)
	--response_payload = compose_payload(url, host, payload, "message")

	--local sock = ngx.socket.tcp()
	--ok, err = sock:connect(host, port)
	--ok, err = sock:send(payload)

	--local httpc = http.new()
	--local res, err = httpc:request_uri(url, params_cache)


	local ssl = require("ssl")

	local cert_file = lfs.currentdir() .. "/ABDevRootCert.pem"
	local params = {
		 mode = "client",
		 protocol = "any",
		 verify = "none",
		 certificate = cert_file,
		 options = "all",
		}

	local conn = socket.tcp()
	ok, err = conn:connect(host, port)

	conn = ssl.wrap(conn, params)
	--conn:dohandshake()
	ok, err = conn:send(payload)


	local latency = 0
	for k, v in pairs(response_header) do
		if k == 'x-kong-proxy-latency' then
			latency = v
		end
	end
	

	local response_string = fmt("<CVLOG907A3>|%s|kong|%s|response|%s000|%s|%s|%s|", log_format_id, unique_id, os.time(os.date("!*t")), latency, kong.client.get_ip(), destination_ip)
	constant_string = fmt("%s\nHTTP/1.1 %s Created\r\n",response_string, response_status)
	local response_payload = compose_payload(constant_string, response_header, resp_body)

	--response_headers["Content-Length"] = #response_payload
	response_headers["Content-Type"] = "text/plain"
	response_params_cache.method = conf.method
	response_params_cache.body = response_payload
	
	--ok, err = sock:send(response_payload)
	--local res, err = httpc:request_uri(url, response_params_cache)
	conn:send(response_payload)

end

function ApiExporterHandler:access(conf)
	get_log_format(conf)

end


function ApiExporterHandler:body_filter(conf)
	response_header, err = kong.response.get_headers()
	resp_body, err = kong.response.get_raw_body()
	destination_ip = kong.request.get_host()
	response_status = kong.response.get_status()
end


function ApiExporterHandler:log(conf)
	local method = kong.request.get_method()
	local url = kong.request.get_path()
	local urlParams = kong.request.get_raw_query()
	
	--get_log_format(conf)
	local output_log = ""

	local header, err = ngx.req.get_headers()
	for k, v in pairs(header) do
		output_log =  fmt("%s%s:%s\n", output_log, k, v)
	end
	
	--kong.log.err("output log: ", output_log)
end
	


return ApiExporterHandler




