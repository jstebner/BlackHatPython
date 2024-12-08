dicom_protocol = Proto("dicom-a", "DICOM A-Type message")

--[[
--	default fields
--]]

pdu_type = ProtoField.uint8("dicom-a.pdu_type", "pduType", base.DEC, {
	[1]="ASSOC Request",
	[2]="Assoc Accept",
	[3]="ASSOC Reject",
	[4]="Data",
	[5]="RELEASE Request",
	[6]="RELEASE Response",
	[7]="ABORT"
}) -- unsigned 8-bit int

message_length = ProtoField.uint16("dicom-a.message_length", "messageLength", base.DEC) -- unsigned 16-bit int

--[[
--	c-echo fields
--]]

protocol_version = ProtoField.uint8("dicom-a.protocol_version", "protocolVersion", base.DEC)

calling_application = ProtoField.string("dicom-a.calling_app", "callingApplication")

called_application = ProtoField.string("dicom-a.called_app", "calledApplication")

dicom_protocol.fields = {pdu_type, message_length}

--[[
--	dissector
--]]

function dicom_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = dicom_protocol.name
	local subtree = tree:add(dicom_protocol, buffer(), "DICOM PDU")
	local pkt_len = buffer(2,4):uint()
	local pdu_id = buffer(0,1):uint() -- convert to unsigned int
	subtree:add_le(pdu_type, buffer(0,1)) -- big endian
	subtree:add(message_length, buffer(2,4)) -- skip 1 byte
	if pdu_id == 1 or pdu_id == 2 then -- ASSOC-REQ (1) / ASSOC-RESP (2)
		local assoc_tree = subtree:add(dicom_protocol, buffer(), "ASSOCIATE REQ/RSP")
		assoc_tree:add(protocol_version, buffer(6,2))
		assoc_tree:add(calling_application, buffer(10,16))
		assoc_tree:add(called_application, buffer(26,16))

		-- extract app context
		local context_variables_length = buffer(76,2):uint()
		local app_context_tree = assoc_tree:add(dicom_protocol, buffer(74, context_variables_length+4), "Application Context")
		app_context_tree:add(app_context_type, buffer(74,1))
		app_context_tree:add(app_context_length, buffer(76,2))
		app_context_tree:add(app_context_name, buffer(78, context_variables_length))

		-- extract presentation context
		local presentation_items_length = buffer(78+context_variables_length+2, 2):uint()
		local presentation_context_tree = assoc_tree:add(dicom_protocol, buffer(78+context_variables_length, presentation_items_length+4), "Presentation Context")
		presentation_context_tree:add(presentation_context_type, buffer(78+context_variables_length, 1))
		presentation_context_tree:add(presentation_context_length, buffer(78+context_variables_length+2, 2))

		-- TODO: extract presentation context items
		
		-- extract user info context
		local user_info_length = buffer(78+context_variables_length+2+presentation_items_length+2+2, 2):uint()
		local user_info_context_tree = assoc_tree:add(dicom_protocol, buffer(78+context_variables_length+presentation_items_length+4, user_info_length+4), "User Info Context")
		user_info_context_tree:add(user_info_length, buffer(78+context_variables_length+2+presentation_items_length+2+2, 2))

		-- TODO: extract user info context items
	end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(4242, dicom_protocol)
