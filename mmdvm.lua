-- create myproto protocol and its fields
p_myproto = Proto ("MMDVM","MMDVM Protocol")
-- local f_command = ProtoField.uint16("myproto.command", "Command", base.HEX)
local f_signature = ProtoField.string("mmdvm.sig", "Signature", base.ASCII)
local f_seq = ProtoField.uint8("mmdvm.seq", "Sequence", base.DEC)
local f_src_id = ProtoField.uint24("mmdvm.src_id", "Source ID", base.DEC)
local f_dst_id = ProtoField.uint24("mmdvm.dst_id", "Destination ID", base.DEC)
local f_rptr_id = ProtoField.uint32("mmdvm.rptr_id", "Repeater ID", base.DEC)
local f_slot = ProtoField.string("mmdvm.slot", "Slot", base.ASCII)
local f_call_type = ProtoField.string("mmdvm.call_type", "Call type", base.ASCII)
local f_frame_type = ProtoField.string("mmdvm.frame_type", "Frame type", base.ASCII)
local f_data_type = ProtoField.string("mmdvm.data_type", "Data type", base.ASCII)
local f_voice_seq = ProtoField.string("mmdvm.voice_seq", "Voice Sequence", base.ASCII)
local f_stream_id = ProtoField.uint32("mmdvm.stream_id", "Stream ID", base.DEC)
local f_dmr_pkt = ProtoField.bytes("mmdvm.date", "DMR Data", base.NONE)
local f_ber = ProtoField.bytes("mmdvm.ber", "BER", base.NONE)
local f_rssi = ProtoField.bytes("mmdvm.rssi", "RSSI", base.NONE)
-- ProtoField.uint24(abbr, [name], [base], [valuestring], [mask], [desc])

local f_data = ProtoField.string("myproto.data", "Data", FT_STRING)
 
p_myproto.fields = {f_signature, f_seq, f_src_id, f_dst_id, f_rptr_id, f_slot, f_call_type, f_frame_type, f_data_type, f_voice_seq, f_stream_id, f_dmr_pkt, f_ber, f_rssi}
 
-- convert hex to string
function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- returns timeslot from MMDVM header
function call_slot(bits)

  bits = bits:bytes()
  bits = bits:get_index(0)
  result = bit.band(bits, 0x80)
  if (result ~= 0) then
    return "2"
  else
    return"1"
  end
end

-- returns call type from MMDVM header
function call_type(bits)

  bits = bits:bytes()
  bits = bits:get_index(0)
  result = bit.band(bits, 0x40)

  if (result ~= 0) then
    return "unit"
  else
    return "group"
  end
end

-- returns frame type from MMDVM header
function frame_type(bits)

  bits = bits:bytes()
  bits = bits:get_index(0)
  bits = bit.band(bits, 0x30)
  result = bit.rshift(bits, 4)
  
  if(result == 0) then
    return "voice"
  elseif (result == 1) then
    return "voice_sync"
  elseif (result == 2) then
    return "data_sync"
  end
end

-- returns data type from MMDVM header
function data_type(bits)

  bits = bits:bytes()
  bits = bits:get_index(0)
  result = bit.band(bits, 0x0F)

  if(result == 1) then
    return "voice_head"
  elseif (result == 2) then
    return "voice_term"
  end
end

-- returns voice sequence from MMDVM header
function voice_seq(bits)
  
  bits = bits:bytes()
  bits = bits:get_index(0)
  result = bit.band(bits, 0x0F)
  if(result == 0) then
    return "A"
  elseif (result == 1) then
    return "B"
  elseif (result == 2) then
    return "C"
  elseif (result == 3) then
    return "D"
  elseif (result == 4) then
    return "E"
  elseif (result == 5) then
    return "F"
  end
end

-- myproto dissector function
function p_myproto.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit

  if buf:len() == 0 then return end
  pkt.cols.protocol = p_myproto.name

  -- create subtree for myproto
  subtree = root:add(p_myproto, buf(0))
  	if (tostring(buf(0,4)):fromhex()) == "DMRD" then

  	  _call_type = call_type(buf(15,1))
  	  _frame_type = frame_type(buf(15,1))

      -- add protocol fields to subtree
      subtree:add(f_signature, buf(0,4))
      subtree:add(f_seq, buf(4,1))
      subtree:add(f_src_id, buf(5,3))
      subtree:add(f_dst_id, buf(8,3))
      subtree:add(f_rptr_id, buf(11,4))
      subtree:add(f_slot, buf(15,1), call_slot(buf(15,1)))
      subtree:add(f_call_type, buf(15,1), _call_type)
      subtree:add(f_frame_type, buf(15,1), _frame_type)

      if _frame_type == "data_sync" then
        subtree:add(f_data_type, buf(15,1), data_type(buf(15,1)))
      else
        subtree:add(f_voice_seq, buf(15,1), voice_seq(buf(15,1)))
      end

      subtree:add(f_stream_id, buf(16,4))
      subtree:add(f_dmr_pkt, buf(20,33))
      if buf:len() >= 55 then
        subtree:add(f_ber, buf(53,1))
        subtree:add(f_rssi, buf(54,1))
      end

    end
end

-- Initialization routine
function p_myproto.init()
end
 
-- register a chained dissector for port 62031
local udp_dissector_table = DissectorTable.get("udp.port")
dissector = udp_dissector_table:get_dissector(62031)
  -- you can call dissector from function p_myproto.dissector above
  -- so that the previous dissector gets called
udp_dissector_table:add(62031, p_myproto)