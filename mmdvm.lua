
-- state handling
local stream_map = {}
local state_map = {}
local socket_map = {}
local f_udp_stream  = Field.new("udp.stream")

-- create myproto protocol and its fields
p_mmdvm = Proto ("MMDVM","MMDVM Protocol")
p_mmdvm_conf = Proto ("MMDVM_Conf","MMDVM Configuration")

-- local f_command = ProtoField.uint16("myproto.command", "Command", base.HEX)
local f_signature = ProtoField.string("mmdvm.sig", "Signature", base.ASCII)
local f_seq = ProtoField.uint8("mmdvm.seq", "Sequence", base.DEC)
local f_len = ProtoField.uint8("mmdvm.len", "Length", base.DEC)
local f_src_id = ProtoField.uint24("mmdvm.src_id", "Source ID", base.DEC)
local f_dst_id = ProtoField.uint24("mmdvm.dst_id", "Destination ID", base.DEC)
local f_rptr_id = ProtoField.uint32("mmdvm.rptr_id", "Repeater ID", base.DEC)
local f_rptr_id_ascii = ProtoField.string("mmdvm.rptr_id_ascii", "Repeater ID", base.ASCII)
local f_slot = ProtoField.string("mmdvm.slot", "Slot", base.ASCII)
local f_call_type = ProtoField.string("mmdvm.call_type", "Call type", base.ASCII)
local f_frame_type = ProtoField.string("mmdvm.frame_type", "Frame type", base.ASCII)
local f_data_type = ProtoField.string("mmdvm.data_type", "Data type", base.ASCII)
local f_voice_seq = ProtoField.string("mmdvm.voice_seq", "Voice Sequence", base.ASCII)
local f_stream_id = ProtoField.uint32("mmdvm.stream_id", "Stream ID", base.DEC)
local f_dmr_pkt = ProtoField.bytes("mmdvm.data", "DMR Data", base.NONE)
local f_dmr_sig = ProtoField.bytes("mmdvm.sig", "OpenBridge Signature", base.NONE)
local f_ber = ProtoField.string("mmdvm.ber", "BER", base.ASCII)
local f_rssi = ProtoField.string("mmdvm.rssi", "RSSI", base.ASCII)

local f_salt = ProtoField.bytes("mmdvm.salt", "Salt", base.NONE)
local f_hash = ProtoField.bytes("mmdvm.hash", "Hash", base.NONE)

local f_call_sign = ProtoField.string("mmdvm.call", "Call Sign", base.ASCII)
local f_rx_freq = ProtoField.string("mmdvm.rx", "Rx Frequency", base.ASCII)
local f_tx_freq = ProtoField.string("mmdvm.tx", "Tx Frequency", base.ASCII)
local f_pwr = ProtoField.string("mmdvm.pwr", "Tx Power", base.ASCII)
local f_color_code = ProtoField.string("mmdvm.cc", "Color Code", base.ASCII)
local f_latitude = ProtoField.string("mmdvm.lat", "Latitude", base.ASCII)
local f_longitude = ProtoField.string("mmdvm.long", "Longitude", base.ASCII)
local f_height = ProtoField.string("mmdvm.height", "Height", base.ASCII)
local f_location = ProtoField.string("mmdvm.loc", "Location", base.ASCII)
local f_description = ProtoField.string("mmdvm.desc", "Description", base.ASCII)
local f_mode = ProtoField.string("mmdvm.mode", "Mode", base.ASCII)
local f_slots = ProtoField.string("mmdvm.slots", "Slots", base.ASCII)
local f_url = ProtoField.string("mmdvm.url", "URL", base.ASCII)
local f_software_id = ProtoField.string("mmdvm.sw", "Software ID", base.ASCII)
local f_package_id = ProtoField.string("mmdvm.pkg", "Package ID", base.ASCII)

local f_options = ProtoField.string("mmdvm.opts", "Options", base.ASCII)

p_mmdvm.fields = {f_signature, f_len, f_seq, f_src_id, f_dst_id, f_rptr_id, f_rptr_id_salt, f_slot, f_call_type,
  f_frame_type, f_data_type, f_voice_seq, f_stream_id, f_dmr_pkt, f_dmr_sig, f_ber, f_rssi, f_salt, f_hash,
  f_call_sign, f_rx_freq, f_tx_freq, f_pwr, f_color_code, f_latitude, f_longitude, f_height, f_location,
  f_description, f_mode, f_slots, f_url, f_software_id, f_package_id, f_options}

-- convert hex to string
function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function round(num, precision)
   return math.floor(num*math.pow(10,precision)+0.5) / math.pow(10,precision)
end

-- removes leading zeros
function rem_zero(x)
  x = x:string()
  return x:match("0*(%d+)")
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

-- returns timeslot from BM MMDVM header
function bm_slot(bits)

  bits = bits(1, 1)
  result = tonumber(bits)
  if result == 0 then
    return "DMO"
  elseif result == 1 then
    return"1"
  elseif result == 2 then
    return"2"
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
  else
    return "unknown"
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
  else
    return "unknown (" .. result ..")"
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
  else
    return ""
  end
end

-- Gets mode and slot from MMDVM header
function mode(bits)
  bits = bits:string()
  bits = tonumber(bits)
  if(bits == 4) then
    return "simplex", ""
  elseif(bits == 3) then
    return "duplex", "1,2"
  elseif(bits == 2) then
    return "duplex", "2"
  elseif(bits == 1) then
    return "duplex", "1"
  else
    return "unknown", ""
  end
end

-- calculates BER from MMDVM header
function ber(bits)
  bits = bits:bytes()
  bits = bits:get_index(0)
  bits = bits / 1.41
  result = tostring(round(bits, 2))
  return result
end

-- calculates RSSI from MMDVM header
function rssi(bits)
  bits = bits:bytes()
  bits = bits:get_index(0)
  result = tostring(bits * -1)
  return result
end

-- converts TG to string
function tg(bits)
    result = bits:uint()
    return result
end

-- init maps on start
function p_mmdvm.init()
    stream_map = {}
    state_map = {}
end

-- mmdvm dissector function
function p_mmdvm.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit

  if buf:len() == 0 then return end
  pkt.cols.protocol = p_mmdvm.name

  -- handle state
  _stream = f_udp_stream().value
  _number = tostring(pkt.number)
  _src_ip = tostring(pkt.src)
  _src_port = tostring(pkt.src_port)
  _dst_ip = tostring(pkt.dst)
  _dst_port = tostring(pkt.dst_port)
  _dst_socket = _dst_ip .. ":" .. _dst_port

  if not pkt.visited then
    if not stream_map[_stream] then
      stream_map[_stream] = {}
    end
  end

  -- info("Number: " .. _number .. " Source: " .. _src_ip .. ":" .. _src_port .. " Destination: " .. _dst_ip .. ":" .. _dst_port)

  -- create subtree for mmdvm
  subtree = root:add(p_mmdvm, buf(0))

    if (tostring(buf(0,4)):fromhex()) == "DMRD" then

      _call_type = call_type(buf(15,1))
      _frame_type = frame_type(buf(15,1))
      _data_type = data_type(buf(15,1))
      _voice_seq = voice_seq(buf(15,1))
      _src_id = tg(buf(5,3))
      _dst_id = tg(buf(8,3))

      if buf:len() == 73 then
        _signed = true
      else
        _signed = false
      end

      _pkt_info = "UNKNOWN"

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
        subtree:add(f_data_type, buf(15,1), _data_type)
        if _data_type == "voice_head" then
          _pkt_info = "VOICE HEADER"
        elseif _data_type == "voice_term" then
          _pkt_info = "VOICE TERM"
        else
          _pkt_info =  string.upper(_data_type)
        end
      else
        subtree:add(f_voice_seq, buf(15,1), _voice_seq)
        if _frame_type == "voice_sync" then
          _pkt_info = "VOICE SYNC  "
        else
          _pkt_info = "VOICE FRAME "
        end
      end

      if socket_map[_dst_socket] then
        _pkt_info = socket_map[_dst_socket] .. ": " .. _pkt_info
      else
        _pkt_info = " UNKNOWN" .. ": " .. _pkt_info
      end

      if _call_type == "unit" then
        _pkt_info = _pkt_info .. " [" .. _src_id .. " -> " .. _dst_id .. " PRIVATE]"
      else
        _pkt_info = _pkt_info .. " [" .. _src_id .. " -> " .. _dst_id .. " GROUP]"
      end

      if _signed then
        _pkt_info = _pkt_info .. " (SIGNED)"
      end

      pkt.cols.info:set(_pkt_info)

      subtree:add(f_stream_id, buf(16,4))
      subtree:add(f_dmr_pkt, buf(20,33))
      if buf:len() == 55 then

        _ber = ber(buf(53,1))
        _rssi = rssi(buf(54,1))

        subtree:add(f_ber, buf(53,1), _ber)
             :append_text("%")
        if tonumber(_rssi) < 0 then
          subtree:add(f_rssi, buf(54,1), _rssi)
                 :append_text("dBm")
        end
      elseif _signed then
        subtree:add(f_dmr_sig, buf(53,20))
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTP" then
      subtree:add(f_signature, buf(0,7))
      subtree:add(f_rptr_id, buf(7,4))
      pkt.cols.info:set("RPT->MST: PING")

      if not pkt.visited then
        socket_map[_dst_socket] = "RPT->MST"
      end


    elseif (tostring(buf(0,4)):fromhex()) == "MSTP" then
      subtree:add(f_signature, buf(0,7))
      subtree:add(f_rptr_id, buf(7,4))
      pkt.cols.info:set("MST->RPT: PONG")

      if not pkt.visited then
        socket_map[_dst_socket] = "MST->RPT"
      end

    elseif (tostring(buf(0,5)):fromhex()) == "RPTCL" then
      subtree:add(f_signature, buf(0,5))
      subtree:add(f_rptr_id, buf(5,4))
      pkt.cols.info:set("RPT->MST: CLOSING DOWN")

      if not pkt.visited then
        socket_map[_dst_socket] = "RPT->MST"
      end

    elseif (tostring(buf(0,4)):fromhex()) == "MSTC" then
      subtree:add(f_signature, buf(0,5))
      subtree:add(f_rptr_id, buf(5,4))
      pkt.cols.info:set("MST->RPT: CLOSING DOWN")

      if not pkt.visited then
        socket_map[_dst_socket] = "MST->RPT"
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTL" then
      subtree:add(f_signature, buf(0,4))
      subtree:add(f_rptr_id, buf(4,4))
      pkt.cols.info:set("RPT->MST: LOGIN INIT")

      if not pkt.visited then
        stream_map[_stream]["STATE"] = "INIT"
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTK" then
      subtree:add(f_signature, buf(0,4))
      subtree:add(f_rptr_id, buf(4,4))
      subtree:add(f_hash, buf(8,(buf:len() - 8)))
      pkt.cols.info:set("RPT->MST: AUTH")

      if not pkt.visited then
        stream_map[_stream]["STATE"] = "AUTH"
        socket_map[_dst_socket] = "RPT->MST"
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTA" then

      subtree:add(f_signature, buf(0,6))

      if not pkt.visited then

         socket_map[_dst_socket] = "MST->RPT"

        if not state_map[_number] then
          state_map[_number] = {}
        end

        if stream_map[_stream]["STATE"] == "INIT" then
            state_map[_number]["STATE"] = "INIT"
            if buf:len() == 10 then
                subtree:add(f_salt, buf(6,4))
                state_map[_number]['MSG'] = "MST->RPT: AUTH CHALLENGE"
            elseif buf:len() == 14 then
                subtree:add(f_rptr_id, buf(6,4))
                subtree:add(f_salt, buf(10,4))
                state_map[_number]['MSG'] = "MST->RPT: AUTH CHALLENGE"
            else
                subtree:add(f_salt, buf(6,4))
                state_map[_number]['MALFORMED'] = true
                state_map[_number]['MSG'] = "MST->RPT: AUTH CHALLENGE [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        elseif stream_map[_stream]["STATE"] == "AUTH" then
            state_map[_number]['STATE'] = "AUTH"
            if buf:len() == 10 then
              subtree:add(f_rptr_id, buf(6,4))
              state_map[_number]['MSG'] = "MST->RPT: AUTH SUCCESSFUL"
            else
              state_map[_number]['MALFORMED'] = true
              state_map[_number]['MSG'] = "MST->RPT: AUTH SUCCESSFUL [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        elseif stream_map[_stream]["STATE"] == "LOGIN" or stream_map[_stream]["STATE"] == "CONF" then
            state_map[_number]['STATE'] = "LOGIN"
            if buf:len() == 10 then
              subtree:add(f_rptr_id, buf(6,4))
              state_map[_number]['MSG'] = "MST->RPT: LOGIN SUCCESSFUL"
            else
              state_map[_number]['MALFORMED'] = true
              state_map[_number]['MSG'] = "MST->RPT: LOGIN SUCCESSFUL [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        elseif stream_map[_stream]["STATE"] == "OPTIONS" then
            state_map[_number]['STATE'] = "LOGIN"
            if buf:len() == 10 then
              subtree:add(f_rptr_id, buf(6,4))
              state_map[_number]['MSG'] = "MST->RPT: OPTIONS SUCCESSFUL"
            else
              state_map[_number]['MALFORMED'] = true
              state_map[_number]['MSG'] = "MST->RPT: OPTIONS SUCCESSFUL [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])
        end

      elseif state_map[_number]['STATE'] ~= "INIT" then
        _message = state_map[_number]['MSG']
        pkt.cols.info:set(_message)
        if not state_map[_number]['MALFORMED'] then
           subtree:add(f_rptr_id, buf(6,4))
        end

      elseif state_map[_number]['STATE'] == "INIT" then
        _message = state_map[_number]['MSG']
        pkt.cols.info:set(_message)
        if buf:len() == 10 then
            subtree:add(f_salt, buf(6,4))
        elseif buf:len() == 14 then
            subtree:add(f_rptr_id, buf(6,4))
            subtree:add(f_salt, buf(10,4))
        end
      end

    elseif (tostring(buf(0,6)):fromhex()) == "MSTNAK" then

      subtree:add(f_signature, buf(0,6))
      info("NAK in frame" .. _number)

      if not pkt.visited then

        info("univsited NAK in frame" .. _number)

        if not state_map[_number] then
          state_map[_number] = {}
        end

        if stream_map[_stream]["STATE"] == "INIT" then
            state_map[_number]["STATE"] = "INIT"
            if buf:len() == 10 then
                subtree:add(f_salt, buf(6,4))
                state_map[_number]['MSG'] = "MST->RPT: LOGIN INIT FAILED"
            else
                state_map[_number]['MALFORMED'] = true
                state_map[_number]['MSG'] = "MST->RPT: LOGIN INIT FAILED [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        elseif stream_map[_stream]["STATE"] == "AUTH" then
            state_map[_number]['STATE'] = "AUTH"
            if buf:len() == 10 then
              subtree:add(f_rptr_id, buf(6,4))
              state_map[_number]['MSG'] = "MST->RPT: AUTH FAILED"
            else
              state_map[_number]['MALFORMED'] = true
              state_map[_number]['MSG'] = "MST->RPT: AUTH FAILED [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        elseif stream_map[_stream]["STATE"] == "CONF" then
            state_map[_number]['STATE'] = "CONF"
            if buf:len() == 10 then
              subtree:add(f_rptr_id, buf(6,4))
              state_map[_number]['MSG'] = "MST->RPT: CONF FAILED"
            else
              state_map[_number]['MALFORMED'] = true
              state_map[_number]['MSG'] = "MST->RPT: CONF FAILED [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        elseif stream_map[_stream]["STATE"] == "OPTIONS" then
            state_map[_number]['STATE'] = "LOGIN"
            if buf:len() == 10 then
              subtree:add(f_rptr_id, buf(6,4))
              state_map[_number]['MSG'] = "MST->RPT: OPTIONS FAILED"
            else
              state_map[_number]['MALFORMED'] = true
              state_map[_number]['MSG'] = "MST->RPT: OPTIONS FAILED [MALFORMED]"
            end
            pkt.cols.info:set(state_map[_number]['MSG'])

        else
          if buf:len() == 10 then
            subtree:add(f_rptr_id, buf(6,4))
            pkt.cols.info:set("MSTNAK")
          else
             pkt.cols.info:set("MSTNAK [MALFORMED]")
          end
        end

      else

        info("visited NAK in frame" .. _number)
        _message = state_map[_number]['MSG']
        pkt.cols.info:set(_message)
        if not state_map[_number]['MALFORMED'] then
           subtree:add(f_rptr_id, buf(6,4))
        end
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTC" then

      _mode, _slots = mode(buf(97,1))

      subtree:add(f_signature, buf(0,4))
      subtree:add(f_rptr_id, buf(4,4))

      conftree = subtree:add(p_mmdvm_conf, buf(8))
      conftree:add(f_call_sign, buf(8,8))
      conftree:add(f_rx_freq, buf(16,9))
      conftree:add(f_tx_freq, buf(25,9))
      conftree:add(f_pwr, buf(34,2), rem_zero(buf(34,2)))
              :append_text("W")
      conftree:add(f_color_code, buf(36,2), rem_zero(buf(36,2)))
      conftree:add(f_latitude, buf(38,8))
      conftree:add(f_longitude, buf(46,9))
      conftree:add(f_height, buf(55,3), rem_zero(buf(55,3)))
              :append_text("M")
      conftree:add(f_location, buf(58,20))
      conftree:add(f_description, buf(78,19))
      conftree:add(f_mode, buf(97,1), _mode)
      if _mode == 'duplex' then
        conftree:add(f_slots, buf(97,1), _slots)
      end
      conftree:add(f_url, buf(98,124))
      conftree:add(f_software_id, buf(222,40))
      conftree:add(f_package_id, buf(262,40))
      pkt.cols.info:set("RPT->MST: CONF")

      if not pkt.visited then
        stream_map[_stream]["STATE"] = "CONF"
        socket_map[_dst_socket] = "RPT->MST"
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTO" then

      subtree:add(f_signature, buf(0,4))
      subtree:add(f_rptr_id, buf(4,4))
      subtree:add(f_options, buf(8,buf:len() - 8 ))
      pkt.cols.info:set("RPT->MST: OPTIONS")

      if not pkt.visited then
        stream_map[_stream]["STATE"] = "OPTIONS"
        socket_map[_dst_socket] = "RPT->MST"
      end

    elseif (tostring(buf(0,4)):fromhex()) == "RPTSBKN" then

      subtree:add(f_signature, buf(0,6))
      subtree:add(f_rptr_id_ascii, buf(6,8))
      pkt.cols.info:set("MST->RPT: BEACON")

      if not pkt.visited then
        socket_map[_dst_socket] = "MST->RPT"
      end

    elseif (tostring(buf(0,7)):fromhex()) == "RPTRSSI" then

      _bm_slot = bm_slot(buf(10,2))

      subtree:add(f_signature, buf(0,7))
      subtree:add(f_rptr_id_ascii, buf(7,8))
      subtree:add(f_slots, buf(15,2), _bm_slot)
      subtree:add(f_rssi, buf(17,5))
             :append_text("dBm")
      pkt.cols.info:set("RPT->MST: RSSI")

      if not pkt.visited then
        socket_map[_dst_socket] = "RPT->MST"
      end

    elseif (tostring(buf(0,7)):fromhex()) == "RPTINTR" then

      _bm_slot = bm_slot(buf(10,2))

      subtree:add(f_signature, buf(0,7))
      subtree:add(f_rptr_id_ascii, buf(7,8))
      subtree:add(f_slots, buf(15,2), _bm_slot)
      pkt.cols.info:set("RPT->MST: CALL INTERRUPT")

      if not pkt.visited then
        socket_map[_dst_socket] = "RPT->MST"
      end

    end
end

-- register a chained dissector for port 62030
local udp_dissector_table = DissectorTable.get("udp.port")
dissector = udp_dissector_table:get_dissector(62031)
  -- you can call dissector from function p_mmdvm.dissector above
  -- so that the previous dissector gets called
udp_dissector_table:add(62031, p_mmdvm)
