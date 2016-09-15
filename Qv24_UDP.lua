-- Simple Quantar Dissector UDP
-- Copyright 2016 John Yaldwyn
-- Release version 1.2 September 2016 for testing
-- This dissector contains the results of investigative work by:
-- Matt Ames (né Robert) VK2LK, Tony Casciato KT9AC, John Yaldwyn ZL4JY,
-- and anonymous contributors.
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, see:
-- http://www.gnu.org/licenses/
-- The use of Wireshark's API are covered by GPL.
-- The dissector looks at naked Quantar V.24 frames carried over UDP.
--
-- Create QV24 protocol and fields
--
p_QV24 = Proto ("QV24_UDP","Quantar V.24 over UDP")
local f_command = ProtoField.uint8("QV24.command", "Frame", base.HEX)
local f_data = ProtoField.string("QV24.data", "Data", FT_STRING)
--
p_QV24.fields = {f_command}
--
-- QV24 dissector function
--
function p_QV24.dissector (buf, pkt, root)
--
-- Validate packet length otherwise quit
--
if buf:len() == 0 then return end
pkt.cols.protocol = p_QV24.name
-- 
-- Frame type decoding
--
	local frame = buf(0,1):uint()
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
  	subtree = root:add(p_QV24, buf(0))  
--
-- Add protocol fields to subtree
	subtree:append_text(": " .. frametext)
--
-- Description of payload
  	subtree:append_text(", payload:")
--
-- Description of bits before and after IMBE codeword
	if frame == 0x62 then 
		subtree:append_text(" LDU1 RSSI= ".. buf(6,1):uint())
		subtree:append_text(", inverse signal= ".. buf(8,1):uint())
		subtree:append_text(", candidate adjusted MM= $".. buf(9,1))
	end
	if frame == 0x63 or frame == 0x6c then
		subtree:append_text(" last byte= $".. buf(13,1))
	end
	if frame == 0x64 then
		if buf(1,1):uint() == 0x00 then subtree:append_text(" Voice 4 contains TGID,")
		elseif buf(1,1):uint() == 0x03 then subtree:append_text(" Voice 4 contains Call target RID,")
		else subtree:append_text(" Link Control Format= $".. buf(1,1))
		end
		if buf(2,1):uint() == 0x00 then subtree:append_text(" MFID= default")
		elseif buf(2,1):uint() == 0x90 then subtree:append_text(" MFID= Motorola")
		elseif buf(2,1):uint() == 0xD8 then subtree:append_text(" MFID= Tait")
		else subtree:append_text(" MFID= $".. buf(2,1))
		end
		if buf(3,1):uint() == 0x40 then subtree:append_text(", encrypted")
		elseif buf(2,1):uint() == 0x90 then subtree:append_text(", legacy encryption")
		elseif buf(2,1):uint() == 0x00 then subtree:append_text(", no encryption")
		end
	end
	if frame == 0x65 then 
		subtree:append_text(" TGID (or Call RID)= ".. buf(1,3):uint())
	end
	if frame == 0x66 then
		subtree:append_text(" RID= ".. buf(1,3):uint())
	end
	if frame == 0x6a then
		subtree:append_text(" LDU1 low speed dat= $".. buf(1,2))
		subtree:append_text(" last byte= $".. buf(15,1))
	end
	if frame == 0x6b then 
		subtree:append_text(" LDU2 RSSI= ".. buf(6,1):uint())
		subtree:append_text(", inverse signal= ".. buf(8,1):uint())
		subtree:append_text(", candidate adjusted MM= $".. buf(9,1))
	end
	if frame == 0x70 then subtree:append_text(" ALGID= $".. buf(1,1))
		if buf(1,1):uint() <= 0x7F then subtree:append_text(": Possible Type 1, be very afraid")
		elseif buf(1,1):uint() == 0x80 then subtree:append_text(": Unencrypted")
		elseif buf(1,1):uint() == 0x81 then subtree:append_text(": DES")
		elseif buf(1,1):uint() == 0x83 then subtree:append_text(": Triple DES")
		elseif buf(1,1):uint() == 0x84 then subtree:append_text(": AES 256")	
		elseif buf(1,1):uint() == 0x85 then subtree:append_text(": AES 128 GCM")
		elseif buf(1,1):uint() == 0x88 then subtree:append_text(": AES CBC")
		elseif buf(1,1):uint() == 0x9F then subtree:append_text(": DES-XL")
		elseif buf(1,1):uint() == 0xA0 then subtree:append_text(": DVI-XL")
		elseif buf(1,1):uint() == 0xA1 then subtree:append_text(": DVP-XL")	
		elseif buf(1,1):uint() == 0xAA then subtree:append_text(": ADP")
		end
		subtree:append_text(", KeyID: $".. buf(2,2))
	end
	if frame == 0xa1 then
		subtree:append_text(" Page target RID= ".. buf(13,3):uint())
	end
	if frame == 0x73 then
		subtree:append_text(" LDU2 low speed dat= $".. buf(1,2))
		subtree:append_text(" last byte= $".. buf(15,1))
	end
end
-- 
-- Initialization routine
function p_QV24.init()
end
-- 
-- Register the chained dissector for port 30000
local udp_dissector_table = DissectorTable.get("udp.port")
dissector = udp_dissector_table:get_dissector(30000)
udp_dissector_table:add(30000, p_QV24)
--
-- END
