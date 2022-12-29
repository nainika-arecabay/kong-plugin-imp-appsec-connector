-- This software is copyright Kong Inc. and its licensors.
-- Use of the software is subject to the agreement between your organization
-- and Kong Inc. If there is no such agreement, use is governed by and
-- subject to the terms of the Kong Master Software License Agreement found
-- at https://konghq.com/enterprisesoftwarelicense/.
-- [ END OF LICENSE 0867164ffc95e54f04670b5169c09574bdbd9bba ]

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
	  { destination_port = { type = "number", default = 8080, one_of = {80, 8080, 8443, 443 }, }, },
          { method = { type = "string", default = "POST", one_of = { "POST", "PUT", "PATCH" }, }, },
          { content_type = { type = "string", default = "application/json", one_of = { "application/json" }, }, },
	  { connection_type = {type = "string", default = "tcp", one_of = { "tcp", "http" }, }, },
	  { ssl = {type = "boolean", default = false}, },
          { custom_fields_by_lua = typedefs.lua_code },
        },
      },
    },
  },
}
