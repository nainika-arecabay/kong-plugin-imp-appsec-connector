--[[
--:module:: handler.lua
--:platform: Linux
--:synopsis: An interface to implement. Each function is to be run by Kong at the desired moment in the lifecycle of a request.
--:copyright: (c) 2022 Imperva Inc. All rights reserved. (This is modified based on tcp-log plugin provided by Kong)
--:moduleauthor: Nainika <nainika.aggarwal@imperva.com> (Nov 19, 2022)
--]]--

local fmt = string.format
local table_insert = table.insert
local table_concat = table.concat
local BatchQueue = require "kong.tools.batch_queue"

local kong = kong
local ngx = ngx


local ApiExporterHandler = {
    PRIORITY = 799,
    VERSION = "2.0.0",
    }

local RESPONSE_STATUS_STRING = {
  ["200"] = "OK",
  ['201'] =  'CREATED',
  ['202'] = 'Accepted',
  ['203'] = 'Partial Information',
  ['304'] = 'Not Modified',
  ['401'] = 'Unauthorized',
  ['403'] = 'Forbidden',
  ['499'] = 'Client Closed Request'
}

local queues = {} -- one queue per unique plugin config

local function compose_payload(constant_string, header, payload)
  local output_log = constant_string
  header["transfer-encoding"] = nil
  for k, v in pairs(header) do
    if  type(v) == 'table' then
      local new_string
      for _, value in pairs(v) do
        if not new_string then
          new_string = {value}
        else
	  table_insert(new_string, value)
        end
      end
      table_insert(output_log, fmt("%s:%s", k, table_concat(new_string, ", ")))
    else
      table_insert(output_log, fmt("%s:%s", k, v))
    end
  end

  if payload then
    table_insert(output_log, fmt("\n%s",payload))
  end
  table_insert(output_log, "<CVLOG907A3>\n")
  return table_concat(output_log, "\n")
end

local function create_connection(conf)
  local ssl_verify = conf.ssl

  local port = conf.destination_port
  local host = conf.destination_addr
  local timeout = conf.timeout

  local conn = ngx.socket.tcp()
  conn:settimeout(timeout)
  local _, err = conn:connect(host, port)

  if err then
    kong.log.err(fmt("Error while connecting to host %s and port %s: %s", host, port, err))
  end

  if ssl_verify then
    local _, err = conn:sslhandshake()
    if err then
      kong.log.err(fmt("Error while TLS handshake for connection %s for host %s and port %s: %s", conn, host, port, err))
    end
  end
  return conn

end

local function get_request_payload(conf, payload, header, destination_ip, path, uniq_id, method)
  local destination_addr = conf.destination_addr
  local unique_id = uniq_id
  local request_string = {fmt("<CVLOG907A3>|CV_LOG_1|kong|%s|request|%s000|0|%s|%s|", unique_id, os.time(os.date("!*t")), ngx.ctx.client_ip, destination_ip)}
  table_insert(request_string, fmt("%s %s HTTP/1.1", method, path))
  local request_payload = compose_payload(request_string, header, payload)

  local message2 = "POST /api/v1/CV_LOG_1" .. " HTTP/1.1\r\nHost: " .. destination_addr .. "\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\nContent-Length: " .. string.len(payload) .. "\r\n\r\n" .. request_payload

  if conf.connection_type == "http" then
    request_payload = message2
  end
  return request_payload

end

local function get_response_payload(conf, response_body, response_header, destination_ip, response_status, uniq_id)
  local destination_addr = conf.destination_addr
  local unique_id = uniq_id
  local latency = 0
  for k, v in pairs(response_header) do
    if k == 'x-kong-proxy-latency' then
      latency = v
    end
  end

  local response_string = {fmt("<CVLOG907A3>|CV_LOG_1|kong|%s|response|%s000|%s|%s|%s|", unique_id, os.time(os.date("!*t")), latency, ngx.ctx.client_ip, destination_ip)}
  table_insert(response_string, fmt("HTTP/1.1 %s %s", response_status, RESPONSE_STATUS_STRING[tostring(response_status)]))
  local response_payload = compose_payload(response_string, response_header, response_body)

  local message2 = "POST /api/v1/CV_LOG_1"  .. " HTTP/1.1\r\nHost: " .. destination_addr .. "\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\nContent-Length: " .. string.len(response_payload) .. "\r\n\r\n" .. response_payload
  if conf.connection_type == "http" then
    response_payload = message2
  end

  return response_payload

end

local function send_payload(conf, payload)--, response_payload)
  local conn = create_connection(conf)
  for _,data in pairs(payload) do
    local _, err = conn:send(data)
    if err then
      kong.log.err(fmt("Error while sending payload %s: %s", payload, err))
    end
  end
  conn:close()
end

local function get_queue_id(conf)
  return fmt("%s:%s:%s:%s",
             conf.destination_addr,
	     conf.destination_port,
             conf.method,
             conf.timeout)
end

function ApiExporterHandler:access(conf)
  ngx.ctx.uniq_id = math.random(100000, 999999)
  ngx.ctx.client_ip = kong.client.get_ip()
  local payload = ""
  if conf.request_body_flag then
    payload = kong.request.get_raw_body()
  end
  local header, _ = ngx.req.get_headers()
  local destination_ip = kong.request.get_host()

  if not destination_ip then
    destination_ip = '0.0.0.0'
  end
  local method = kong.request.get_method()
  local path = kong.request.get_path()
  ngx.ctx.request_body = get_request_payload(conf, payload, header, destination_ip, path, ngx.ctx.uniq_id, method)
  ngx.ctx.resp_body = ""
end

function ApiExporterHandler:body_filter(conf)
  if conf.response_body_flag and conf.max_body_size > 0 then
    local chunk, eof = ngx.arg[1], ngx.arg[2]
    local buffered = ngx.ctx.buffered
    if not buffered then
      buffered = {}
      ngx.ctx.buffered = buffered
    end
    if chunk ~= "" then
      buffered[#buffered + 1] = chunk
      ngx.ctx.buffered = buffered
      ngx.arg[1] = nil
    end

    if eof then
      ngx.ctx.resp_body = table.concat(buffered)
      ngx.ctx.buffered = nil
      ngx.arg[1] = ngx.ctx.resp_body
    end
  else
    ngx.ctx.resp_body = ""
  end
end

function ApiExporterHandler:log(conf)
  local response_header = kong.response.get_headers()
  local destination_ip = kong.request.get_host()
  if not destination_ip then
    destination_ip = '0.0.0.0'
  end
  local response_status = kong.response.get_status()

  local resp_body_len = #ngx.ctx.resp_body
  local responsestr = "{\"message\": \"Response size limit exceeded\", \"size\":" .. resp_body_len .. "}"
  if resp_body_len > conf.max_body_size then
    response_header['content-encoding'] = nil
    ngx.ctx.resp_body =  responsestr
  end

  local response_payload = get_response_payload(conf, ngx.ctx.resp_body, response_header, destination_ip, response_status, ngx.ctx.uniq_id)
  local request_payload = ngx.ctx.request_body

  local queue_id = get_queue_id(conf)
  local q = queues[queue_id]
  if not q then
    local batch_max_size =  conf.queue_size or 1
    local process = function(entries)
      return send_payload(conf, entries)
    end
    local opts = {
      retry_count    = conf.retry_count,
      flush_timeout  = conf.flush_timeout,
      batch_max_size = batch_max_size,
      process_delay  = 0,
    }

    local err
    q, err = BatchQueue.new('imp-appsec-connector', process, opts)
    if not q then
      kong.log.err("could not create queue: ", err)
    end
    queues[queue_id] = q
  end
  q:add(request_payload)
  q:add(response_payload)
end

return ApiExporterHandler
