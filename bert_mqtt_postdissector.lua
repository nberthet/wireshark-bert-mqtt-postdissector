-- Post process MQTT message and decodes them as BERT payloads
--
-- See BERT RPC - http://bert-rpc.org/
-- See External Term Format - http://erlang.org/doc/apps/erts/erl_ext_dist.html
do
  -- bert types
  local TYPES = {
    SMALL_INTEGER_EXT = 97,
    INTEGER_EXT       = 98,
    FLOAT_EXT         = 99,
    ATOM_EXT          = 100,
    SMALL_ATOM_EXT    = 115,
    
    SMALL_TUPLE_EXT   = 104,
    LARGE_TUPLE_EXT   = 105,
    NIL_EXT           = 106,
    STRING_EXT        = 107,
    LIST_EXT          = 108,
    BINARY_EXT        = 109,
    SMALL_BIG_EXT     = 110,
    LARGE_BIG_EXT     = 111,
  }

  bert_proto = Proto("bert", "Binary ERlang Term")
  bert_proto.fields.bert_magic_field  = ProtoField.uint16("bert.magic",       "Magic")
  bert_proto.fields.data_field        = ProtoField.string("bert.data",        "Data")
  bert_proto.fields.data_bytes_field  = ProtoField.uint32("bert.data.bytes",  "Bytes")
  bert_proto.fields.int_field         = ProtoField.uint32("bert.int",         "Int")
  bert_proto.fields.float_field       = ProtoField.string("bert.float",       "Float")
  bert_proto.fields.atom_field        = ProtoField.string("bert.atom",        "Atom")
  bert_proto.fields.nil_field         = ProtoField.string("bert.nil",         "nil")
  bert_proto.fields.string_field      = ProtoField.string("bert.string",      "String")
  bert_proto.fields.tuple_field       = ProtoField.string("bert.tuple",       "Tuple")
  bert_proto.fields.tuple_arity_field = ProtoField.uint32("bert.tuple.arity", "Arity")
  bert_proto.fields.tuple_bytes_field = ProtoField.uint32("bert.tuple.bytes", "Bytes")
  bert_proto.fields.list_field        = ProtoField.string("bert.list",        "List")
  bert_proto.fields.list_length_field = ProtoField.string("bert.list.length", "Length")
  bert_proto.fields.list_bytes_field  = ProtoField.string("bert.list.bytes",  "Bytes")
  bert_proto.fields.binary_field      = ProtoField.string("bert.binary",      "Binary")
  bert_proto.fields.bigint_field      = ProtoField.string("bert.bigint",      "Big Integer")

  local function parse_int(tvb, offset, tree, value_length)
    local value_length = value_length or 4
    local tvb_range = tvb:range(offset + 1, value_length)
    local value = tvb_range:int()
    return offset + 1 + value_length, tree:add(bert_proto.fields.int_field, tvb_range, value), "" .. value
  end
  
  local function parse_small_int(tvb, offset, tree)
    local value_length = 1
    local tvb_range = tvb:range(offset + 1, value_length)
    local value = tvb_range:uint()
    return offset + 1 + value_length, tree:add(bert_proto.fields.int_field, tvb_range, value), "" .. value
  end
  
  local function parse_float(tvb, offset, tree)
    -- Floats are stored as strings, don't bother converting
    local value = tvb:string(offset + 1, 31)
    return offset + 32, tree:add(bert_proto.fields.float_field, value), value
  end
  
  local function parse_atom(tvb, offset, tree, size_length)
    size_length = size_length or 2
    local length = tvb:range(offset + 1, size_length):int()
    local tvb_range = tvb:range(offset + 1 + size_length, length)
    local value = tvb_range:string()
    return offset + 1 + size_length + length, tree:add(bert_proto.fields.atom_field, tvb_range, value), value
  end
  
  local function parse_small_atom(tvb, offset, tree)
    return parse_atom(tvb, offset, tree, 1)
  end
  
  local function parse_elements(tvb, offset, tree, n)
    local text
    local asText = ""
    for i = 1,n do
      offset, subtree, text = parse_bert(tvb, offset, tree)
      subtree:prepend_text("" .. i .. ". ")
      if i > 1 then
        asText = asText .. ", "
      end
      asText = asText .. text
    end
    return offset, asText
  end
  
  local function parse_tuple(tvb, offset, tree, size_length)
    size_length = size_length or 4
    local start_offset = offset
    
    local arity = tvb:range(offset + 1, size_length):int()
    offset = offset + 1 + size_length
    
    local subtree = tree:add(bert_proto.fields.tuple_field, "", "Tuple(" .. arity .. "): ")
    subtree:add(bert_proto.fields.tuple_arity_field, arity):set_generated()
    
    offset, asText = parse_elements(tvb, offset, subtree, arity)
    subtree:append_text(asText)
    
    subtree:add(bert_proto.fields.tuple_bytes_field, offset - start_offset):set_generated()
    
    return offset, subtree, "{" .. asText .. "}"
  end
  
  local function parse_small_tuple(tvb, offset, tree)
    return parse_tuple(tvb, offset, tree, 1)
  end
  
  local function parse_nil(tvb, offset, tree)
    return offset + 1, tree:add(bert_proto.fields.nil_field, "", "nil"), "nil"
  end
  
  local function parse_string(tvb, offset, tree)
    local length = tvb:range(offset + 1, 2):uint()
    local tvb_range = tvb:range(offset + 3, length)
    local value = tvb_range:string()
    return offset + 3 + length, tree:add(bert_proto.fields.string_field, tvb_range, value), "<<\"" .. value .. "\">>"
  end
  
  local function parse_binary(tvb, offset, tree)
    local length = tvb:range(offset + 1, 4):uint()
    local tvb_range = tvb:range(offset + 5, length)
    local value = tvb_range:string()
    return offset + 5 + length, tree:add(bert_proto.fields.binary_field, tvb_range, value), "<<\"" .. value .. "\">>"
  end
  
  local function parse_list(tvb, offset, tree)
    local start_offset = offset
    
    local length = tvb:range(offset + 1, 4):int()
    offset = offset + 1 + 4
    
    local subtree = tree:add(bert_proto.fields.list_field, "", "List(" .. length .. "): ")
    subtree:add(bert_proto.fields.list_length_field, length):set_generated()
    
    local tail
    offset, asText = parse_elements(tvb, offset, subtree, length)
    subtree:append_text(asText)
    
    offset, tail, _ = parse_bert(tvb, offset, subtree)
    tail:prepend_text("(Tail) ")
    
    subtree:add(bert_proto.fields.list_bytes_field, offset - start_offset):set_generated()
    
    return offset, subtree, "[" .. asText .. "]"
  end
  
  local function parse_big(tvb, offset, tree, size_length)
    size_length = size_length or 4
    local n = tvb:range(offset + 1, size_length):uint()
    local sign = tvb:range(offset + 1 + size_length, 1):uint()
    local value_range = tvb:range(offset + 1 + size_length + 1, n)
    offset = offset + 1 + size_length + 1 + n
    if n < 8 then
      local value = (sign * (-2) + 1) * value_range:le_uint64()
      return offset, tree:add(bert_proto.fields.bigint_field, value_range, "" .. value), "" .. value
    else
      return offset, tree:add(bert_proto.fields.bigint_field, value_range, "??"), "?BitInt?"
    end
  end
  
  local function parse_small_big(tvb, offset, tree)
    return parse_big(tvb, offset, tree, 1)
  end
  
  function parse_bert(tvb, offset, tree)
    local tag = tvb:range(offset, 1):int()
    
    local handlers = {
      [TYPES.SMALL_INTEGER_EXT] = parse_small_int,
      [TYPES.INTEGER_EXT]       = parse_int,
      [TYPES.FLOAT_EXT]         = parse_float,
      [TYPES.ATOM_EXT]          = parse_atom,
      [TYPES.SMALL_ATOM_EXT]    = parse_small_atom,
      [TYPES.SMALL_TUPLE_EXT]   = parse_small_tuple,
      [TYPES.LARGE_TUPLE_EXT]   = parse_tuple,
      [TYPES.NIL_EXT]           = parse_nil,
      [TYPES.STRING_EXT]        = parse_string,
      [TYPES.LIST_EXT]          = parse_list,
      [TYPES.BINARY_EXT]        = parse_binary,
      [TYPES.SMALL_BIG_EXT]     = parse_small_big,
      [TYPES.LARGE_BIG_EXT]     = parse_big
    }
    
    if handlers[tag] then
      return handlers[tag](tvb, offset, tree)
    else
      return offset, tree:add(bert_proto.fields.string_field, "", "Unknown tag " .. tag .. " (offset = " .. offset .. ")"), "Unknown"
    end
  end
  
  local mqtt_msg =   Field.new("mqtt.msg")
  
  function bert_proto.dissector(buffer, pkt_info, tree)
    local fields = { all_field_infos() }
    
    if mqtt_msg() then
        local bert_tree = tree:add(bert_proto)
        local tvb = mqtt_msg().source
        local range = mqtt_msg().range
        
        bert_tree:add(bert_proto.fields.bert_magic_field, tvb:range(range:offset(), 1) )
  
        local data_tree = bert_tree:add(bert_proto.fields.data_field, "")
        local offset,root,text = parse_bert(tvb, range:offset() + 1, data_tree)
        local bert_data_size = offset - range:offset()
        
        local bert_length = bert_tree:add(bert_proto.fields.data_bytes_field, bert_data_size)
        bert_length:set_generated()
        
        bert_tree:append_text(", " .. bert_data_size .. " bytes")
        data_tree:append_text(text)
        pkt_info.cols['info']:append(" <- BERT(" .. text .. ")")
        pkt_info.cols['protocol']:prepend("BERT+")
    end
  end
  
  register_postdissector(bert_proto)
end
