-- This software is copyright Imperva Inc. and its licensors.
-- Use of the software is subject to the agreement between your organization
-- and Kong Inc. If there is no such agreement, use is governed by and
-- subject to the terms of the Kong Master Software License Agreement found
-- at https://konghq.com/enterprisesoftwarelicense/.

local typedefs = require "kong.db.schema.typedefs"
local url = require "socket.url"

return {
  name = "log-consumer",
  fields = {
    { protocols = typedefs.protocols },
    { config = {
        type = "record",
        fields = {
          -- NOTE: any field added here must be also included in the handler's get_queue_id method
          { destination_addr = {type =  'string', required = true, encrypted = true },}, -- encrypted = true is a Kong-Enterprise exclusive feature, does nothing in Kong CE
	  { destination_port = { type = "number", required = true, default = 8080 }, },
          { method = { type = "string", default = "POST", one_of = { "POST", "PUT", "PATCH" }, }, },
	  { connection_type = {type = "string", default = "tcp", one_of = { "tcp", "http" }, }, },
	  { timeout = {type = "number", default = 6000000 }, },
	  { max_body_size = {type = "number", default = 1048576 }, },
	  { ssl = {type = "boolean", default = false}, },
	  { request_body_flag = {type = "boolean", default = true}, },
	  { response_body_flag = {type = "boolean", default = true}, },
	  { retry_count = { type = "integer", default = 0 }, },
	  { queue_size = { type = "integer", default = 1 }, },
	  { flush_timeout = { type = "number", default = 2 }, },
          { custom_fields_by_lua = typedefs.lua_code },
        },
      },
    },
  },
}
