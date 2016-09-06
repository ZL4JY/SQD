-- Simple Quantar Dissector TCP
-- Copyright 2016 John Yaldwyn ZL4JY
-- Release version 1.1 September 2016 for testing
-- This dissector contains the resutls of investigative work by:
-- Matt Robert-Ames VK2LK, Tony Casciato KT9AC, John Yaldwyn ZL4JY,
-- and anonymous contributors.
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, see:
-- http://www.gnu.org/licenses/
-- The use of Wireshark's API are covered by GPL
-- The TCP dissector looks at Cisco STUN encapsualted V.24 at port 1994.
--
-- Create QV24 protocol and its fields
--
p_QV24T = Proto ("QV24_TCP","Quantar V.24 over TCP")
local f_command = ProtoField.uint16("QV24T.command", "Command", base.HEX)
local f_data = ProtoField.string("QV24T.data", "Data", FT_STRING)
-- 
p_QV24T.fields = {f_command}
-- 
-- QV24 dissector function
--
function p_QV24T.dissector (buf, pkt, root)
--
-- Validate packet length is adequate, otherwise quit
--
if buf:len() == 0 then return end
pkt.cols.protocol = p_QV24T.name
--
-- 
-- Frame type decoding, note offset to skip Cisco STUN encapsualtion
--
	local frame = buf(9,1):uint()
	local frametext = "undefined"
	if frame == 0x00 then frametext = "Start" 
	elseif frame == 0x60 then frametext = "Voice Header Part 1"
	elseif frame == 0x61 then frametext = "Voice Header Part 2" 
	elseif frame == 0x62 then frametext = "IMBE Voice 1" 
	elseif frame == 0x63 then frametext = "IMBE Voice 2"
	elseif frame == 0x64 then frametext = "IMBE Voice 3 + Link Control"
	elseif frame == 0x65 then frametext = "IMBE Voice 4 + Link Control"
	elseif frame == 0x66 then frametext = "IMBE Voice 5 + Link Control"
	elseif frame == 0x67 then frametext = "IMBE Voice 6 + Link Control"
	elseif frame == 0x68 then frametext = "IMBE Voice 7 + Link Control"
	elseif frame == 0x69 then frametext = "IMBE Voice 8 + Link Control"
	elseif frame == 0x6a then frametext = "IMBE Voice 9 + Low Speed Data"
	elseif frame == 0x6b then frametext = "IMBE Voice 10"
	elseif frame == 0x6c then frametext = "IMBE Voice 11"
	elseif frame == 0x6d then frametext = "IMBE Voice 12 + Encryption Sync"
	elseif frame == 0x6e then frametext = "IMBE Voice 13 + Encryption Sync"
	elseif frame == 0x6f then frametext = "IMBE Voice 14 + Encryption Sync"
	elseif frame == 0x70 then frametext = "IMBE Voice 15 + Encryption Sync"
	elseif frame == 0x71 then frametext = "IMBE Voice 16 + Encryption Sync"
	elseif frame == 0x72 then frametext = "IMBE Voice 17 + Encryption Sync"
	elseif frame == 0x73 then frametext = "IMBE Voice 18 + Low Speed Data"
	elseif frame == 0xa1 then frametext = "Page call frame"
	end
-- 
pkt.cols.info = frametext
--
-- Create subtree for QV24
	subtree = root:add(p_QV24T, buf(9))  
--
-- Add protocol fields to subtree
	subtree:append_text(": " .. frametext)
--
-- Description of payload
	subtree:append_text(", payload")
--
-- Description of bits before and after IMBE codeword
	if frame == 0x62 then 
		subtree:append_text(" RSSI= ".. buf(15,1):uint())
		subtree:append_text(", inverse signal= ".. buf(17,1):uint())
	end
	if frame == 0x63 or frame == 0x6c then
		subtree:append_text(" last byte= $".. buf(22,1))
	end
	if frame == 0x64 then
		if buf(10,1):uint() == 0x00 then subtree:append_text(" Voice 4 contains TGID,")
		elseif buf(10,1):uint() == 0x03 then subtree:append_text(" Voice 4 contains Call target RID,")
		else subtree:append_text(" function byte= $".. buf(10,1))
		end
		if buf(12,1):uint() == 0x40 then subtree:append_text(" encrypted")
		elseif buf(12,1):uint() == 0x90 then subtree:append_text(" legacy encryption")
		elseif buf(12,1):uint() == 0x00 then subtree:append_text(" no encryption")
		end
	end
	if frame == 0x65 then 
		subtree:append_text(" TGID (or Call RID)= ".. buf(10,3):uint())
	end
	if frame == 0x66 then
		subtree:append_text(" RID= ".. buf(10,3):uint())
	end
	if frame == 0x6a then
		subtree:append_text(" LDU1 low speed dat= $".. buf(10,2))
		subtree:append_text(" last byte= $".. buf(24,1))
	end
	if frame == 0x70 then subtree:append_text(" ALGID= $".. buf(10,1))
		if buf(10,1):uint() <= 0x7F then subtree:append_text(": Possible Type 1, be very afraid")
		elseif buf(10,1):uint() == 0x80 then subtree:append_text(": Unencrypted")
		elseif buf(10,1):uint() == 0x81 then subtree:append_text(": DES")
		elseif buf(10,1):uint() == 0x83 then subtree:append_text(": Triple DES")
		elseif buf(10,1):uint() == 0x84 then subtree:append_text(": AES 256")	
		elseif buf(10,1):uint() == 0x85 then subtree:append_text(": AES 128 GCM")
		elseif buf(10,1):uint() == 0x88 then subtree:append_text(": AES CBC")
		elseif buf(10,1):uint() == 0x9F then subtree:append_text(": DES-XL")
		elseif buf(10,1):uint() == 0xA0 then subtree:append_text(": DVI-XL")
		elseif buf(10,1):uint() == 0xA1 then subtree:append_text(": DVP-XL")	
		elseif buf(10,1):uint() == 0xAA then subtree:append_text(": ADP")
		end
		subtree:append_text(", KeyID: $".. buf(11,2))
	end
	if frame == 0xa1 then
		subtree:append_text(" Page trget RID= ".. buf(22,3):uint())
	end
	if frame == 0x73 then
		subtree:append_text(" LDU2 low speed dat= $".. buf(10,2))
		subtree:append_text(", last byte= $".. buf(24,1))
	end
end
-- 
-- Initialization routine
function p_QV24T.init()
end
-- 
-- Register the chained dissector for port 1994
local tcp_dissector_table = DissectorTable.get("tcp.port")
dissector = tcp_dissector_table:get_dissector(1994)
tcp_dissector_table:add(1994, p_QV24T)
--
-- END


