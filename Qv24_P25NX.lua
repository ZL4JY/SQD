-- Simple Quantar Dissector UDP for P25NX
-- Copyright 2016 John Yaldwyn ZL4JY
-- Release version 2 November 2016 for testing
-- This dissector contains the resutls of investigative work by:
-- Matt Ames (né Robert) VK2LK, Tony Casciato KT9AC, John Yaldwyn ZL4JY,
-- and anonymous contributors.  Input also from DG9BEW.
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, see:
-- http://www.gnu.org/licenses/
-- The use of Wireshark's API are covered by GPL
-- The UDP dissector looks at Cisco STUN encapsualted V.24 frames carried P25NX V2 style.
--
-- Create QV24 protocol and its fields
--
p_QV24 = Proto ("QV24_P25NX","Quantar V.24 over TCP or UDP - P25NX")
local hdr_fields =
{
    stun_payload_length =                       ProtoField.new (
                                                    "Payload Length",
                                                    "cisco_stun.payload_length" ,
                                                    ftypes.UINT8
                                                ),
    stun_id =                                   ProtoField.new (
                                                    "STUN ID",
                                                    "cisco_stun.id" ,
                                                    ftypes.UINT8
                                                ),
    hdlc_address =                      ProtoField.new (
                                                    "HDLC Address",
                                                    "hdlc.address" ,
                                                    ftypes.UINT8
                                                ),
    hdlc_control_field =                ProtoField.new (
                                                    "Control Field",
                                                    "hdlc.control_field" ,
                                                    ftypes.UINT8,
                                                    nil,
                                                    base.HEX,
                                                    0xFF
                                                ),
    hdlc_poll_final =                   ProtoField.new (
                                                    "Poll/Final",
                                                    "hdlc.poll_final" ,
                                                    ftypes.UINT8,
                                                    {
                                                        [0] = "Poll",
                                                        [1] = "Final"
                                                    },
                                                    base.HEX,
                                                    0x10
                                                ),
    hdlc_frame_type_informational =     ProtoField.new (
                                                    "Frame Type",
                                                    "hdlc.frame_type" ,
                                                    ftypes.UINT8,
                                                    {
                                                        [0] = "Informational Frame",
                                                        [1] = "Supervisory Frame",
                                                        [2] = "Informational Frame",
                                                        [3] = "Unnumbered Frame"
                                                    },
                                                    base.HEX,
                                                    0x01
                                                ),
    hdlc_frame_type_supervisory =       ProtoField.new (
                                                    "Frame Type",
                                                    "hdlc.frame_type" ,
                                                    ftypes.UINT8,
                                                    {
                                                        [0] = "Informational Frame",
                                                        [1] = "Supervisory Frame",
                                                        [2] = "Informational Frame",
                                                        [3] = "Unnumbered Frame"
                                                    },
                                                    base.HEX,
                                                    0x03
                                                ),
    hdlc_frame_type_unnumbered =        ProtoField.new (
                                                    "Frame Type",
                                                    "hdlc.frame_type" ,
                                                    ftypes.UINT8,
                                                    {
                                                        [0] = "Informational Frame",
                                                        [1] = "Supervisory Frame",
                                                        [2] = "Informational Frame",
                                                        [3] = "Unnumbered Frame"
                                                    },
                                                    base.HEX,
                                                    0x03
                                                ),
    hdlc_function_bits_supervisory =    ProtoField.new (
                                                    "Function Bits",
                                                    "hdlc.function_bits" ,
                                                    ftypes.UINT8,
                                                    {
                                                        [0] = "Receive-Ready",
                                                        [1] = "Receive-Not-Ready",
                                                        [2] = "Reject",
                                                        [3] = "Selective-Reject"
                                                    },
                                                    base.HEX,
                                                    0x0c
                                                ),
    hdlc_function_bits_unnumbered =     ProtoField.new (
                                                    "Function Bits",
                                                    "hdlc.function_bits",
                                                    ftypes.UINT8,
                                                    {
                                                        [0] = "Unnumbered Information",
                                                        [1] = "Set/Request Init.Mode",
                                                        [2] = "",
                                                        [3] = "Set Async. Response Mode"
                                                    },
                                                    base.HEX,
                                                    0xec
                                                ),
    p25_frametype =             ProtoField.new (
                                       "Frame Type",
                                        "qv24_p25nx.frametype",
                                        ftypes.UINT8,
                                        {
                                            [0x00] = "NID Start/Stop",
                                            [0x60] = "Voice Header Part 1",
                                            [0x61] = "Voice Header Part 2",
                                            [0x62] = "IMBE Voice 1",
                                            [0x63] = "IMBE Voice 2",
                                            [0x64] = "IMBE Voice 3 + Link Control",
                                            [0x65] = "IMBE Voice 4 + Link Control",
                                            [0x66] = "IMBE Voice 5 + Link Control",
                                            [0x67] = "IMBE Voice 6 + Link Control",
                                            [0x68] = "IMBE Voice 7 + Link Control",
                                            [0x69] = "IMBE Voice 8 + Link Control",
                                            [0x6a] = "IMBE Voice 9 + Low Speed Data",
                                            [0x6b] = "IMBE Voice 10",
                                            [0x6c] = "IMBE Voice 11",
                                            [0x6d] = "IMBE Voice 12 + Encryption Sync",
                                            [0x6e] = "IMBE Voice 13 + Encryption Sync",
                                            [0x6f] = "IMBE Voice 14 + Encryption Sync",
                                            [0x70] = "IMBE Voice 15 + Encryption Sync",
                                            [0x71] = "IMBE Voice 16 + Encryption Sync",
                                            [0x72] = "IMBE Voice 17 + Encryption Sync",
                                            [0x73] = "IMBE Voice 18 + Low Speed Data",
                                            [0xa1] = "Page call frame",
                                        },
                                        base.HEX
                                    ),
    p25_rt_rt_enabled =         ProtoField.new ("RT/RT enabled", "qv24_p25nx.rt_rt", ftypes.UINT8, {
                                            [0x02] = "RT/RT enabled",
                                            [0x04] = "RT/RT disabled",
                                        }, base.HEX),
    p25_site_number =           ProtoField.new ("Site Number", "qv24_p25nx.site_number", ftypes.UINT8, {
                                            [0x1b] = "Quantar",
                                            [0x00] = "DIU 3000",
                                        }, base.HEX),
    p25_voice_page =            ProtoField.new ("Voice/Page", "qv24_p25nx.voice_page", ftypes.UINT8, {
                                            [0x0b] = "Voice",
                                            [0x0f] = "Page",
                                        }, base.HEX),
    p25_rssi =                  ProtoField.new ("RSSI", "qv24_p25nx.rssi" , ftypes.UINT8),
    p25_inverse_signal =        ProtoField.new ("Inverse Signal", "qv24_p25nx.inverse_signal" , ftypes.UINT8),
    p25_candidate_adj_mm =      ProtoField.new ("Candidate adjusted MM", "qv24_p25nx.candidate_adj_mm", ftypes.UINT8),
    p25_last_byte =             ProtoField.new ("Last Byte", "qv24_p25nx.last_byte", ftypes.UINT8),
    p25_lcf =                   ProtoField.new (
                                        "Link Control Format", 
                                        "qv24_p25nx.lcf", 
                                        ftypes.UINT8, 
                                        {
                                            [0x00] = "Group Voice Channel User",
                                            [0x42] = "Group Voice Channel Update",
                                            [0x03] = "Unit to Unit Voice Channel User",
                                            [0x44] = "Group Voice Channel Update - Explicit",
                                            [0x45] = "Unit to Unit Answer Request",
                                            [0x46] = "Telephone Interconnect Voice Channel User",
                                            [0x47] = "Telephone Interconnect Answer Request",
                                            [0x4F] = "Call Termination/Cancellation",
                                            [0x50] = "Group Affiliation Query",
                                            [0x51] = "Unit Registration Command",
                                            [0x52] = "Unit Authentication Command",
                                            [0x53] = "Status Query",
                                            [0x60] = "System Service Broadcast",
                                            [0x61] = "Secondary Control Channel Broadcast",
                                            [0x62] = "Adjacent Site Status Broadcast",
                                            [0x63] = "RFSS Status Broadcast",
                                            [0x64] = "Network Status Broadcast",
                                            [0x54] = "Status Update",
                                            [0x55] = "Message Update",
                                            [0x56] = "Call Alert",
                                            [0x57] = "Extended Function Command",
                                            [0x58] = "Channel Identifier Update",
                                            [0x65] = "Protection Parameter Broadcast",
                                            [0x66] = "Secondary Control Channel Broadcast - Explicit (LCSCBX)",
                                            [0x67] = "Adjacent Site Status Broadcast – Explicit (LCASBX)",
                                            [0x59] = "Channel Identifier Update – Explicit (LCCIUX)",
                                            [0x68] = "RFSS Status Broadcast – Explicit (LCRSBX)",
                                            [0x69] = "Network Status Broadcast – Explicit (LCNSBX)",

                                            [0x80] = "Encrypted Group Voice Channel User",
                                            [0xc2] = "Encrypted Group Voice Channel Update",
                                            [0x83] = "Encrypted Unit to Unit Voice Channel User",
                                            [0xc4] = "Encrypted Group Voice Channel Update - Explicit",
                                            [0xc5] = "Encrypted Unit to Unit Answer Request",
                                            [0xc6] = "Encrypted Telephone Interconnect Voice Channel User",
                                            [0xc7] = "Encrypted Telephone Interconnect Answer Request",
                                            [0xcF] = "Encrypted Call Termination/Cancellation",
                                            [0xd0] = "Encrypted Group Affiliation Query",
                                            [0xd1] = "Encrypted Unit Registration Command",
                                            [0xd2] = "Encrypted Unit Authentication Command",
                                            [0xd3] = "Encrypted Status Query",
                                            [0xe0] = "Encrypted System Service Broadcast",
                                            [0xe1] = "Encrypted Secondary Control Channel Broadcast",
                                            [0xe2] = "Encrypted Adjacent Site Status Broadcast",
                                            [0xe3] = "Encrypted RFSS Status Broadcast",
                                            [0xe4] = "Encrypted Network Status Broadcast",
                                            [0xd4] = "Encrypted Status Update",
                                            [0xd5] = "Encrypted Message Update",
                                            [0xd6] = "Encrypted Call Alert",
                                            [0xd7] = "Encrypted Extended Function Command",
                                            [0xd8] = "Encrypted Channel Identifier Update",
                                            [0xe5] = "Encrypted Protection Parameter Broadcast",
                                        },
                                        base.HEX, 
                                        0xFF
                                    ),
    p25_lcf_protected_flag =    ProtoField.new (
                                        "Protected Flag", 
                                        "qv24_p25nx.lcf_protected_flag", 
                                        ftypes.UINT8, 
                                        {
                                            [0] = "Not encrypted",
                                            [1] = "Encrypted",
                                        },
                                        base.HEX, 
                                        0x80
                                    ),
    p25_lcf_mfid_format =       ProtoField.new (
                                        "Implicit / Explicit MFID Format", 
                                        "qv24_p25nx.lcf_mfid_format", 
                                        ftypes.UINT8, 
                                        {
                                            [0] = "Implicit, MFID 0 is implied",
                                            [1] = "Explicit",
                                        },
                                        base.HEX, 
                                        0x40
                                    ),
    p25_lcf_link_control_opcode = ProtoField.new (
                                        "Link Control Opcode", 
                                        "qv24_p25nx.lcf_link_control_opcode", 
                                        ftypes.UINT8, 
                                        {},
                                        base.HEX, 
                                        0x3F
                                    ),
    p25_mfid =                  ProtoField.new (
                                        "Manufacturer's ID", 
                                        "qv24_p25nx.mfid", 
                                        ftypes.UINT8, 
                                        {
                                            [0x00] = "default value",
                                            [0x01] = "another default value",
                                            [0x09] = "Aselsan Inc.",
                                            [0x10] = "Relm/BK Radio",
                                            [0x18] = "Airbus",
                                            [0x20] = "Cycomm",
                                            [0x28] = "Efratom",
                                            [0x30] = "Com-Net Ericsson",
                                            [0x34] = "Etherstack",
                                            [0x38] = "Datron",
                                            [0x40] = "Icom",
                                            [0x48] = "Garmin",
                                            [0x50] = "GTE",
                                            [0x55] = "IFR Systems",
                                            [0x5A] = "INIT Innovations",
                                            [0x60] = "GEC-Marconi",
                                            [0x64] = "Harris Corp (inactive)",
                                            [0x68] = "Kenwood",
                                            [0x70] = "Glenayre Electronics",
                                            [0x74] = "Japan Radio Co.",
                                            [0x78] = "Kokusai",
                                            [0x7c] = "Maxon",
                                            [0x80] = "Midland",
                                            [0x86] = "Daniels Electronics",
                                            [0x90] = "Motorola",
                                            [0xa0] = "Thales",
                                            [0xa4] = "Harris Corporation",
                                            [0xAA] = "NRPC",
                                            [0xb0] = "Raytheon",
                                            [0xc0] = "SEA",
                                            [0xc8] = "Securicor",
                                            [0xd0] = "ADI",
                                            [0xD8] = "Tait Electronics",
                                            [0xe0] = "Teletec",
                                            [0xf0] = "Transcrypt International",
                                            [0xF8] = "Vertex Standard",
                                            [0xFC] = "Zetron, Inc.",
                                        },
                                        base.HEX
                                    ),
    p25_service_options =           ProtoField.new (
                                        "Service Options", 
                                        "qv24_p25nx.service_options", 
                                        ftypes.UINT8, 
                                        {},
                                        base.HEX, 
                                        0xFF
                                    ),
    p25_service_options_emergency = ProtoField.new (
                                        "Emergency Flag", 
                                        "qv24_p25nx.service_options_emergency", 
                                        ftypes.UINT8, 
                                        {
                                            [0] = "Normal or non-emergency status",
                                            [1] = "Emergency status requiring special processing",
                                        },
                                        base.HEX, 
                                        0x80
                                    ),
    p25_service_options_protected = ProtoField.new (
                                        "Protected Flag", 
                                        "qv24_p25nx.service_options_protected", 
                                        ftypes.UINT8, 
                                        {
                                            [0] = "non protected mode",
                                            [1] = "protected mode",
                                        },
                                        base.HEX, 
                                        0x40
                                    ),
    p25_service_options_duplex =    ProtoField.new (
                                        "Duplex Flag", 
                                        "qv24_p25nx.service_options_duplex", 
                                        ftypes.UINT8, 
                                        {
                                            [0] = "half duplex, the subscriber unit will be capable of transmitting but not simultaneously receiving on the assigned channel",
                                            [1] = "full duplex, the subscriber unit will be capable of transmitting and receiving simultaneously on the assigned channel",
                                        },
                                        base.HEX, 
                                        0x20
                                    ),
    p25_service_options_mode =      ProtoField.new (
                                        "Data Mode Flag", 
                                        "qv24_p25nx.service_options_mode", 
                                        ftypes.UINT8, 
                                        {
                                            [0] = "circuit mode - the resources shall support circuit switch operation",
                                            [1] = "packet mode - the resources shall support packet switch operation",
                                        },
                                        base.HEX, 
                                        0x10
                                    ),
    p25_service_options_priority =  ProtoField.new (
                                        "Priority", 
                                        "qv24_p25nx.service_options_priority", 
                                        ftypes.UINT8, 
                                        {},
                                        base.HEX, 
                                        0x07
                                    ),
    p25_target_address =            ProtoField.new (
                                        "Target Address/Radio ID", 
                                        "qv24_p25nx.target_address", 
                                        ftypes.UINT24, 
                                        {
                                            [1]     = "Local",
                                            [10100] = "Worldwide",
                                            [10101] = "WW Tac1",
                                            [10102] = "WW Tac2",
                                            [10103] = "WW Tac3",
                                            [10200] = "North America",
                                            [10201] = "NORTAC1",
                                            [10202] = "NORTAC2",
                                            [10203] = "NORTAC3",
                                            [10235] = "Florida",
                                            [10250] = "California",
                                            [10251] = "NorCal",
                                            [10252] = "SoCal",
                                            [10300] = "Europe",
                                            [10301] = "EURTAC1",
                                            [10302] = "EURTAC2",
                                            [10303] = "EURTAC4",
                                            [10310] = "France",
                                            [10320] = "Germany",
                                            [10400] = "Pacific",
                                            [10401] = "PACTAC1",
                                            [10402] = "PACTAC2",
                                            [10403] = "PACTAC3",
                                        },
                                        base.DEC
                                    ),
    p25_source_address =            ProtoField.new (
                                        "Source Address/Radio ID", 
                                        "qv24_p25nx.source_address", 
                                        ftypes.UINT24, 
                                        p25_radio_ids,
                                        base.DEC
                                    ),
    p25_low_speed_data =            ProtoField.new (
                                        "Low speed data", 
                                        "qv24_p25nx.low_speed_data", 
                                        ftypes.UINT16, 
                                        {},
                                        base.HEX
                                    ),
    p25_enc_iv =                    ProtoField.new (
                                        "Encryption initialization vector/Message Indicator", 
                                        "qv24_p25nx.enc_iv", 
                                        ftypes.BYTES, 
                                        {},
                                        base.NONE
                                    ),
    p25_algid =                     ProtoField.new (
                                        "Algorithm ID", 
                                        "qv24_p25nx.algid", 
                                        ftypes.UINT8, 
                                        {
                                            [0x00] = "ACCORDION 1.3",
                                            [0x01] = "BATON (Auto Even)",
                                            [0x02] = "FIREFLY Type 1",
                                            [0x03] = "MAYFLY Type 1",
                                            [0x04] = "SAVILLE",
                                            [0x41] = "BATON (Auto Odd)",
                                            [0x80] = "Unencrypted",
                                            [0x81] = "DES",
                                            [0x83] = "Triple DES",
                                            [0x84] = "AES 256",
                                            [0x85] = "AES 128 GCM",
                                            [0x88] = "AES CBC",
                                            [0x9F] = "DES-XL",
                                            [0xA0] = "DVI-XL",
                                            [0xA1] = "DVP-XL",
                                            [0xAA] = "ADP",
                                        },
                                        base.HEX
                                    ),
    p25_keyid =                     ProtoField.new (
                                        "Key ID", 
                                        "qv24_p25nx.keyid", 
                                        ftypes.UINT16, 
                                        {},
                                        base.HEX
                                    ),
}
p_QV24.fields = hdr_fields
-- 
-- QV24 dissector function
--
function p_QV24.dissector (buf, pkt, root)
	--
	-- Validate packet length is adequate, otherwise quit
	--
	local pktlen = buf:len() 
    if pktlen < 7 then 
        -- frame to short to contains STUN
        return 0
	end

    local bytes_consumed = 0
    while bytes_consumed < pktlen do
        local stun_tvbr = buf(0 + bytes_consumed, 7)
        local stun_payload_length_tvbr = stun_tvbr(5, 1)
        local stun_payload_length = stun_payload_length_tvbr:uint()
        local stun_id_tvbr = stun_tvbr(6, 1)
        local stun_id = stun_id_tvbr:uint()
        local stun_payload_tvbr = buf(7 + bytes_consumed, stun_payload_length)
        local stun_tree = root:add(stun_tvbr, "Cisco STUN")
        stun_tree:add(hdr_fields.stun_id, stun_id_tvbr)
        stun_tree:add(hdr_fields.stun_payload_length, stun_payload_length_tvbr)
        pkt.cols.info:set("Cisco STUN")
        pkt.cols.protocol:set("Cisco STUN")

        if stun_payload_tvbr:len() >= 2 then
            local hdlc_tvbr = stun_payload_tvbr(0, 2)
            local hdlc_address_tvbr = hdlc_tvbr(0, 1)
            local hdlc_address = hdlc_address_tvbr:uint()
            local hdlc_control_field_tvbr = hdlc_tvbr(1, 1)
            local hdlc_control_field = hdlc_control_field_tvbr:uint()
            local hdlc_tree = root:add(hdlc_tvbr, "Quantar HDLC")
            pkt.cols.info:set("Quantar HDLC")
            pkt.cols.protocol:set("Quantar HDLC")

            local frame_type_bits = 0
            if hdlc_control_field % 2 > 0 then
                 if ((hdlc_control_field - (hdlc_control_field % 2)) / 2) % 2 > 0 then
                    -- Unnumbered frame
                    frame_type_bits = 3
                    hdlc_tree:add(hdr_fields.hdlc_frame_type_unnumbered, hdlc_control_field_tvbr)
                    hdlc_tree:add(hdr_fields.hdlc_function_bits_unnumbered, hdlc_control_field_tvbr)
                else
                    -- Supervisory frame
                    frame_type_bits = 1
                    hdlc_tree:add(hdr_fields.hdlc_frame_type_supervisory, hdlc_control_field_tvbr)
                    hdlc_tree:add(hdr_fields.hdlc_function_bits_supervisory, hdlc_control_field_tvbr)
                    local function_bits = hdlc_control_field_tvbr:bitfield(4,2)
                    if function_bits == 0 then 
                        pkt.cols.info:set("Receive-Ready")
                    elseif function_bits == 1 then 
                        pkt.cols.info:set("Receive-Not-Ready")
                    elseif function_bits == 2 then 
                        pkt.cols.info:set("Reject")
                    elseif function_bits == 3 then 
                        pkt.cols.info:set("Selective-Reject")
                    end
                end
            else
                -- Information frame
                frame_type_bits = 0
                hdlc_tree:add(hdr_fields.hdlc_frame_type_informational, hdlc_control_field_tvbr)
            end

            local poll_final = hdlc_control_field_tvbr:uint()
            hdlc_tree:add(hdr_fields.hdlc_poll_final, hdlc_control_field_tvbr)

            if stun_payload_tvbr:len() > 2 then
                local p25_tvbr = stun_payload_tvbr(2)

                pkt.cols.protocol:set(p_QV24.name)
                local tree = root:add(p_QV24, p25_tvbr)
                local frame_type_tvbr = p25_tvbr(0,1)
                local frame_type = frame_type_tvbr:uint()
                tree:add(hdr_fields.p25_frametype, frame_type_tvbr)
                local frame_type_text =  { 
                                            [0x00] = "NID Start/Stop",
                                            [0x01] = "undefined",
                                            [0x59] = "undefined",
                                            [0x60] = "Voice Header Part 1", 
                                            [0x61] = "Voice Header Part 2", 
                                            [0x62] = "IMBE Voice 1", 
                                            [0x63] = "IMBE Voice 2",
                                            [0x64] = "IMBE Voice 3 + Link Control",
                                            [0x65] = "IMBE Voice 4 + Link Control",
                                            [0x66] = "IMBE Voice 5 + Link Control",
                                            [0x67] = "IMBE Voice 6 + Link Control",
                                            [0x68] = "IMBE Voice 7 + Link Control",
                                            [0x69] = "IMBE Voice 8 + Link Control",
                                            [0x6a] = "IMBE Voice 9 + Low Speed Data",
                                            [0x6b] = "IMBE Voice 10",
                                            [0x6c] = "IMBE Voice 11",
                                            [0x6d] = "IMBE Voice 12 + Encryption Sync",
                                            [0x6e] = "IMBE Voice 13 + Encryption Sync",
                                            [0x6f] = "IMBE Voice 14 + Encryption Sync",
                                            [0x70] = "IMBE Voice 15 + Encryption Sync",
                                            [0x71] = "IMBE Voice 16 + Encryption Sync",
                                            [0x72] = "IMBE Voice 17 + Encryption Sync",
                                            [0x73] = "IMBE Voice 18 + Low Speed Data",
                                            [0xa1] = "Page call frame",
                                        }
                pkt.cols.info:set(frame_type_text[frame_type])
                if frame_type == 0x00 then
                    local p25_rt_rt_enabled_tvbr = p25_tvbr(2,1)
                    local rt_rt_enabled = p25_rt_rt_enabled_tvbr:uint()
                    tree:add(hdr_fields.p25_rt_rt_enabled, p25_rt_rt_enabled_tvbr)

                    local p25_voice_page_tvbr = p25_tvbr(4,1)
                    local voice_page = p25_voice_page_tvbr:uint()
                    tree:add(hdr_fields.p25_voice_page, p25_voice_page_tvbr)

                    if p25_tvbr(3,1):uint() == 0x0c then 
                        pkt.cols.info:set("ICW start")
                    elseif p25_tvbr(3,1):uint() == 0x25 then 
                        pkt.cols.info:set("ICW terminate")
                    end
                elseif frame_type == 0x60 then
                    local p25_rt_rt_enabled_tvbr = p25_tvbr(2,1)
                    tree:add(hdr_fields.p25_rt_rt_enabled, p25_rt_rt_enabled_tvbr)

                    local p25_voice_page_tvbr = p25_tvbr(4,1)
                    tree:add(hdr_fields.p25_voice_page, p25_voice_page_tvbr)

                    local p25_site_number_tvbr = p25_tvbr(5,1)
                    tree:add(hdr_fields.p25_site_number, p25_site_number_tvbr)

                    local p25_rssi_tvbr = p25_tvbr(6,1)
                    tree:add(hdr_fields.p25_rssi, p25_rssi_tvbr)

                    local p25_inverse_signal_tvbr = p25_tvbr(8,1)
                    tree:add(hdr_fields.p25_inverse_signal, p25_inverse_signal_tvbr)
                elseif frame_type == 0x62 then
                    local p25_rt_rt_enabled_tvbr = p25_tvbr(2,1)
                    tree:add(hdr_fields.p25_rt_rt_enabled, p25_rt_rt_enabled_tvbr)

                    local p25_voice_page_tvbr = p25_tvbr(4,1)
                    tree:add(hdr_fields.p25_voice_page, p25_voice_page_tvbr)

                    local p25_site_number_tvbr = p25_tvbr(5,1)
                    tree:add(hdr_fields.p25_site_number, p25_site_number_tvbr)

                    local p25_rssi_tvbr = p25_tvbr(6,1)
                    tree:add(hdr_fields.p25_rssi, p25_rssi_tvbr)

                    local p25_inverse_signal_tvbr = p25_tvbr(8,1)
                    tree:add(hdr_fields.p25_inverse_signal, p25_inverse_signal_tvbr)

                    local p25_candidate_adj_mm_tvbr = p25_tvbr(9,1)
                    tree:add(hdr_fields.p25_candidate_adj_mm, p25_candidate_adj_mm_tvbr)
                elseif frame_type == 0x63 then
                    local p25_last_byte_tvbr = p25_tvbr(13,1)
                    tree:add(hdr_fields.p25_last_byte, p25_last_byte_tvbr)
                elseif frame_type == 0x64 then
                    local p25_lcf_tvbr = p25_tvbr(1,1)
                    tree:add(hdr_fields.p25_lcf, p25_lcf_tvbr)
                    tree:add(hdr_fields.p25_lcf_protected_flag, p25_lcf_tvbr)
                    tree:add(hdr_fields.p25_lcf_mfid_format, p25_lcf_tvbr)
                    tree:add(hdr_fields.p25_lcf_link_control_opcode, p25_lcf_tvbr)
                    local lcf_mfid_format = p25_lcf_tvbr:bitfield(1,1)

                    if lcf_mfid_format == 0 then
                        local p25_mfid_tvbr = p25_tvbr(2,1)
                        tree:add(hdr_fields.p25_mfid, p25_mfid_tvbr)
                        local p25_service_options_tvbr = p25_tvbr(3,1)
                        tree:add(hdr_fields.p25_service_options, p25_service_options_tvbr)
                        tree:add(hdr_fields.p25_service_options_emergency, p25_service_options_tvbr)
                        tree:add(hdr_fields.p25_service_options_protected, p25_service_options_tvbr)
                        tree:add(hdr_fields.p25_service_options_duplex, p25_service_options_tvbr)
                        tree:add(hdr_fields.p25_service_options_mode, p25_service_options_tvbr)
                        tree:add(hdr_fields.p25_service_options_priority, p25_service_options_tvbr)
                    else
                        tree:add("uncommon LCF, will be decoded in later version")
                    end
                elseif frame_type == 0x65 then
                    local p25_target_address_tvbr = p25_tvbr(1,3)
                    tree:add(hdr_fields.p25_target_address, p25_target_address_tvbr)
                elseif frame_type == 0x66 then
                    local p25_source_address_tvbr = p25_tvbr(1,3)
                    tree:add(hdr_fields.p25_source_address, p25_source_address_tvbr)
                elseif frame_type == 0x67 then

                elseif frame_type == 0x68 then

                elseif frame_type == 0x69 then

                elseif frame_type == 0x6a then
                    local p25_low_speed_data_tvbr = p25_tvbr(2,2)
                    tree:add(hdr_fields.p25_low_speed_data, p25_low_speed_data_tvbr)
                elseif frame_type == 0x6b then
                    local p25_rt_rt_enabled_tvbr = p25_tvbr(2,1)
                    tree:add(hdr_fields.p25_rt_rt_enabled, p25_rt_rt_enabled_tvbr)
                    local p25_voice_page_tvbr = p25_tvbr(4,1)
                    tree:add(hdr_fields.p25_voice_page, p25_voice_page_tvbr)
                    local p25_site_number_tvbr = p25_tvbr(5,1)
                    tree:add(hdr_fields.p25_site_number, p25_site_number_tvbr)

                    local p25_rssi_tvbr = p25_tvbr(6,1)
                    tree:add(hdr_fields.p25_rssi, p25_rssi_tvbr)

                    local p25_inverse_signal_tvbr = p25_tvbr(8,1)
                    tree:add(hdr_fields.p25_inverse_signal, p25_inverse_signal_tvbr)

                    local p25_candidate_adj_mm_tvbr = p25_tvbr(9,1)
                    tree:add(hdr_fields.p25_candidate_adj_mm, p25_candidate_adj_mm_tvbr)
                elseif frame_type == 0x6c then

                elseif frame_type == 0x6d then
                    local p25_enc_iv_tvbr = p25_tvbr(1,3)
                    tree:add(hdr_fields.p25_enc_iv, p25_enc_iv_tvbr)
                elseif frame_type == 0x6e then
                    local p25_enc_iv_tvbr = p25_tvbr(1,3)
                    tree:add(hdr_fields.p25_enc_iv, p25_enc_iv_tvbr)
                elseif frame_type == 0x6f then
                    local p25_enc_iv_tvbr = p25_tvbr(1,3)
                    tree:add(hdr_fields.p25_enc_iv, p25_enc_iv_tvbr)
                elseif frame_type == 0x70 then
                    local p25_algid_tvbr = p25_tvbr(1,1)
                    tree:add(hdr_fields.p25_algid, p25_algid_tvbr)
                    local p25_keyid_tvbr = p25_tvbr(2,2)
                    tree:add(hdr_fields.p25_keyid, p25_keyid_tvbr)
                elseif frame_type == 0x71 then

                elseif frame_type == 0x72 then

                elseif frame_type == 0x73 then
                    local p25_low_speed_data_tvbr = p25_tvbr(2,2)
                    tree:add(hdr_fields.p25_low_speed_data, p25_low_speed_data_tvbr)
                elseif frame_type == 0xa1 then
                    local emergency_flags_tvbr = p25_tvbr(9,1)
                    local emergency_flags = emergency_flags_tvbr:uint()
                    if emergency_flags == 0x9F then
                        tree:add(emergency_flags_tvbr, "Page")
                        local p25_source_address_tvbr = p25_tvbr(13,3)
                        tree:add(hdr_fields.p25_source_address, p25_source_address_tvbr)
                        local p25_target_address_tvbr = p25_tvbr(17,2)
                        tree:add(hdr_fields.p25_target_address, p25_target_address_tvbr)
                    elseif emergency_flags == 0xA7 then
                        tree:add(emergency_flags_tvbr, "EMERGENCY")
                        local p25_source_address_tvbr = p25_tvbr(16,3)
                        tree:add(hdr_fields.p25_source_address, p25_source_address_tvbr)
                        local p25_target_address_tvbr = p25_tvbr(14,2)
                        tree:add(hdr_fields.p25_target_address, p25_target_address_tvbr)
                    end 
                end
            end
        else
            -- payload less than 2 bytes
            return 0
        end
        bytes_consumed = bytes_consumed + stun_payload_length + 7
    end
return bytes_consumed
end
-- 
-- Initialization routine
function p_QV24.init()
end
-- 
-- Register the chained dissector for UDP port 30000
local udp_dissector_table = DissectorTable.get("udp.port")
dissector = udp_dissector_table:get_dissector(30000)
udp_dissector_table:add(30000, p_QV24)
--
-- Register the chained dissector for TCP port 1994
local tcp_dissector_table = DissectorTable.get("tcp.port")
dissector = tcp_dissector_table:get_dissector(1994)
tcp_dissector_table:add(1994, p_QV24)
--
-- END


