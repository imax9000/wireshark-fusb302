--[[

Wireshark dissector for Onsemi FUSB302-series controllers

It's not complete by any means, add more fields as you go. Can be used together
with https://github.com/imax9000/wireshark-i2c-dispatch.

--]]

--[[

Copyright 2024 Max Ignatenko

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

--]]

local prev_dissector = DissectorTable.get("i2c.message"):get_dissector(nil)

local fusb302proto = Proto("onsemi_fusb302", "Onsemi FUSB302-series USB Type-C controller")
local txProto = Proto("onsemi_fusb302.tx_fifo", "TX bytes (Onsemi FUSB302-series)")
local rxProto = Proto("onsemi_fusb302.rx_fifo", "RX bytes (Onsemi FUSB302-series)")
local usbPDProto = Proto("usb_pd", "USB Power Delivery")

local txToken = ProtoField.uint8("onsemi_fusb302.tx_fifo.token", "TX token", base.HEX, {
    [0x12] = "SOP1",
    [0x13] = "SOP2",
    [0x1B] = "SOP3",
    [0x15] = "RESET1",
    [0x16] = "RESET2",
    [0xFF] = "JAM_CRC",
    [0x14] = "EOP",
    [0xFE] = "TXOFF",

    [0xA1] = "TXON",
    [0x80] = "PACKSYM",
})
local txBytesLen = ProtoField.uint8("onsemi_fusb302.tx_fifo.token.literal_length",
    "Number of following bytes to send as is", base.DEC, nil, 0x1f)
local txLiteralBytes = ProtoField.bytes("onsemi_fusb302.tx_fifo.bytes", "Bytes to send")

txProto.fields = { txToken, txBytesLen, txLiteralBytes }


local rxSOP = ProtoField.uint8("onsemi_fusb302.rx_fifo.sop_type", "SOP token", base.HEX, {
    -- Wireshark shifts the bits down, so hex values don't match the datasheet.
    [0x7] = "SOP",
    [0x6] = "SOP1",
    [0x5] = "SOP2",
    [0x4] = "SOP1DB",
    [0x3] = "SOP2DB",
}, 0xE0)
local rxLiteralBytes = ProtoField.bytes("onsemi_fusb302.rx_fifo.bytes", "Received payload")
local rxChecksum = ProtoField.bytes("onsemi_fusb302.rx_fifo.checksum", "Payload checksum")

rxProto.fields = { rxSOP, rxLiteralBytes, rxChecksum }

local i2c_addr = Field.new("i2c.addr")
local i2c_flags = Field.new("i2c.flags")

local fifo_register = 0x43

local registers = {}
local register_names = {}
local all_fields = {}

local Register = {}
function Register:new(r)
    setmetatable(r, self)
    self.__index = self
    r.fields = r.fields or {}
    r.bits = r.bits or {}
    r.alwaysPrint = r.alwaysPrint or {}
    registers[r.addr] = r
    register_names[r.addr] = r.description

    r.self_field = ProtoField.uint8(string.format("onsemi_fusb302.%s", r.name), r.description, base.HEX, nil)
    table.insert(all_fields, r.self_field)

    return r
end

function Register:add_field(name, desc, bitmask)
    local f = ProtoField.uint8(
        string.format("onsemi_fusb302.%s.%s", self.name, name),
        desc, base.HEX, nil, bitmask)
    table.insert(all_fields, f)
    table.insert(self.fields, f)
end

function Register:add_bit(pos, name, desc, alwaysPrint)
    local f = ProtoField.bool(
        string.format("onsemi_fusb302.%s.%s", self.name, name),
        desc, 8, nil, bit.lshift(1, pos))
    table.insert(all_fields, f)
    table.insert(self.fields, f)
    self.bits[pos] = name
    if alwaysPrint then self.alwaysPrint[pos] = true end
end

function Register:annotate(treeitem, tvb)
    local t = treeitem:add(self.self_field, tvb)

    for i, f in ipairs(self.fields) do
        t:add(f, tvb)
    end
    return self:describe_value(tvb:uint())
end

function Register:describe_value(v)
    if #self.bits > 0 then
        local setBits = {}
        for pos, name in pairs(self.bits) do
            if bit.band(v, bit.lshift(1, pos)) > 0 then
                table.insert(setBits, name)
            elseif self.alwaysPrint[pos] then
                table.insert(setBits, string.format("!%s", name))
            end
        end
        if #setBits == 0 then
            return "none"
        end
        return table.concat(setBits, " ")
    end
    return string.format("0x%02x", v)
end

do
    local device_id = Register:new { addr = 0x01, name = "device_id", description = "Device ID" }
    device_id:add_field("version", "Version", 0xf0)
    device_id:add_field("revision", "Revision", 0x0f)

    local switches0 = Register:new { addr = 0x02, name = "switches0", description = "Switches0" }
    switches0:add_bit(0, "PDWN1", "Connect CC1 to internal pull-down")
    switches0:add_bit(1, "PDWN2", "Connect CC2 to internal pull-down")
    switches0:add_bit(2, "MEAS_CC1", "Connect CC1 to Measure block")
    switches0:add_bit(3, "MEAS_CC2", "Connect CC2 to Measure block")
    switches0:add_bit(4, "VCONN_CC1", "Supply VCONN voltage to CC1")
    switches0:add_bit(5, "VCONN_CC2", "Supply VCONN voltage to CC2")
    switches0:add_bit(6, "PU_EN1", "Connect CC1 to internal pull-up")
    switches0:add_bit(7, "PU_EN2", "Connect CC2 to internal pull-up")

    local switches1 = Register:new { addr = 0x03, name = "switches1", description = "Switches1" }
    switches1:add_bit(0, "TXCC1", "Enable BMC transmit driver on CC1 pin")
    switches1:add_bit(1, "TXCC2", "Enable BMC transmit driver on CC2 pin")
    switches1:add_bit(2, "AUTO_CRC", "Automatically respond to valid messages with GoodCRC")
    switches1:add_bit(4, "DATAROLE", "Port Data Role to provide in GoodCRC responses (0 = Sink, 1 = Source)")
    switches1:add_field("SPECREV", "Spec revision to provide in GoodCRC responses (00 = 1.0, 01 = 2.0)", 0x60)
    switches1:add_bit(7, "POWERROLE", "Port Power Role to provide in GoodCRC responses (0 = Sink, 1 = Source)")


    local measure = Register:new { addr = 0x04, name = 'measure', description = 'Measure' }
    local slice = Register:new { addr = 0x05, name = 'slice', description = 'Slice' }

    local control0 = Register:new { addr = 0x06, name = 'control0', description = 'Control0' }
    control0:add_bit(0, "TX_START", "Start sending data buffered in FIFO")
    control0:add_bit(6, "TX_FLUSH", "Flush transmit FIFO")

    local control1 = Register:new { addr = 0x07, name = 'control1', description = 'Control1' }
    control1:add_bit(2, "RX_FLUSH", "Flush receive FIFO")

    local control2 = Register:new { addr = 0x08, name = 'control2', description = 'Control2' }

    local control3 = Register:new { addr = 0x09, name = 'control3', description = 'Control3' }
    control3:add_bit(0, "AUTO_RETRY", "Enable automatic retries")
    control3:add_field("N_RETRIES", "Number of retries", 0x06)

    local mask1 = Register:new { addr = 0x0A, name = 'mask1', description = 'Mask1' }

    local power = Register:new { addr = 0x0B, name = 'power', description = 'Power' }
    power:add_bit(0, "bandgap_and_wake", "Bandgap and wake circuit")
    power:add_bit(1, "receiver", "Receiver powered and current references for Measure block")
    power:add_bit(2, "measure", "Measure block powered")
    power:add_bit(3, "oscillator", "Enable internal oscillato")

    local reset = Register:new { addr = 0x0c, name = "reset", description = "Reset" }
    reset:add_bit(0, "SW_RES", "Reset the IC")
    reset:add_bit(1, "PD_RESET", "Reset only the PD logic state")

    local ocp_reg = Register:new { addr = 0x0D, name = 'ocp_reg', description = 'OCPreg' }
    local maska = Register:new { addr = 0x0E, name = 'maska', description = 'Maska' }
    local maskb = Register:new { addr = 0x0F, name = 'maskb', description = 'Maskb' }

    local status0a = Register:new { addr = 0x3C, name = 'status0a', description = 'Status0a' }
    status0a:add_bit(0, "HARDRST", "Received Hard Reset signal")
    status0a:add_bit(1, "SOFTRST", "Received Soft Reset signal")
    status0a:add_bit(2, "POWER2", "Internal state bit corresponding to bit 2 of Power register")
    status0a:add_bit(3, "POWER3", "Internal state bit corresponding to bit 3 of Power register")
    status0a:add_bit(4, "RETRYFAIL", "All retries to send the last packet have failed")
    status0a:add_bit(5, "SOFTFAIL", "All attempts to send Soft Reset have failed")

    local status1a = Register:new { addr = 0x3D, name = 'status1a', description = 'Status1a' }
    local interrupta = Register:new { addr = 0x3E, name = 'interrupta', description = 'Interrupta' }
    local interruptb = Register:new { addr = 0x3F, name = 'interruptb', description = 'Interruptb' }
    local status0 = Register:new { addr = 0x40, name = 'status0', description = 'Status0' }

    local status1 = Register:new { addr = 0x41, name = 'status1', description = 'Status1' }
    status1:add_bit(2, "TX_FULL", "Transmit queue full")
    status1:add_bit(3, "TX_EMPTY", "Transmit queue empty")
    status1:add_bit(4, "RX_FULL", "Receive queue full")
    status1:add_bit(5, "RX_EMPTY", "Receive queue empty", true)

    local interrupt = Register:new { addr = 0x42, name = 'interrupt', description = 'Interrupt' }


    local fifo = Register:new { addr = fifo_register, name = 'fifo', description = 'FIFO' }
end


local register_name = ProtoField.uint8("onsemi_fusb302.register", "Register address", base.HEX, register_names)
table.insert(all_fields, register_name)

fusb302proto.fields = all_fields

local Conversation = {}
function Conversation:new()
    r = {
        tx_chunks = {},
        rx_chunks = {},
        tx_breaks = {},
        rx_breaks = {},
        reg_read = {},
        maxNum = 0,
    }
    setmetatable(r, self)
    self.__index = self
    return r
end

function Conversation:lastRequestedReg(pinfo)
    for i = pinfo.number - 1, 0, -1 do
        if self.reg_read[i] then
            return self.reg_read[i]
        end
    end
    return -1
end

local conversations = {}

function getConversation()
    local f = i2c_addr()
    if f == nil then
        return nil
    end

    local addr = f.value
    if conversations[addr] == nil then
        conversations[addr] = Conversation:new()
    end
    return conversations[addr]
end

function annotateRegisterValue(subtreeitem, tvb, register_addr)
    local r = registers[register_addr]
    if r ~= nil then
        return r:annotate(subtreeitem, tvb)
    end
    return ""
end

function annotateTxBuf(tvb, pinfo, treeitem)
    local t = treeitem:add(txProto, tvb)
    local skip_until = -1
    local packet = ByteArray.new()
    for i = 0, tvb:len() - 1 do
        if i >= skip_until then
            local b = tvb(i, 1):uint()
            if b == 0x12 or b == 0x13 or b == 0x1B or b == 0x15 or b == 0x16 or b == 0xFF or b == 0x14 or b == 0xFE then
                t:add(txToken, tvb(i, 1))
                if packet:len() > 0 and b == 0xFF then
                    local pd_frame = packet:tvb("USB PD message")
                    local pd = treeitem:add(usbPDProto, pd_frame)
                    usbPDProto.dissector(pd_frame, pinfo, pd)
                end
            elseif bit.band(b, 0xE1) == 0xA1 then
                t:add(txToken, tvb(i, 1), 0xA1)
            elseif bit.band(b, 0xE0) == 0x80 then
                local len = bit.band(b, 0x1F)
                skip_until = i + 1 + len
                t:add(txToken, tvb(i, 1), 0x80)
                t:add(txBytesLen, tvb(i, 1))
                if len > tvb:len() - i - 1 then
                    len = tvb:len() - i - 1
                end
                packet:append(tvb(i + 1, len):bytes())
                t:add(txLiteralBytes, tvb(i + 1, len))
            end
        end
    end
    return tvb:len()
end

function annotateRxBuf(tvb, pinfo, treeitem)
    local t = treeitem:add(rxProto, tvb)
    local i = 0
    while i < tvb:len() do
        -- XX YY YY ...
        -- XX - SOP token
        -- YY YY - 16-bit PD header
        t:add(rxSOP, tvb(i, 1))

        -- XXX: peek into the payload to determine packet length.
        -- FUSB302 does not provide any way to determine packet length, or
        -- even how many bytes are in the buffer in total.
        if tvb:len() - i - 1 >= 2 then
            local nPDO = bit.band(bit.rshift(tvb(i + 2, 1):uint(), 4), 0x7)
            local len = 2 + nPDO * 4
            if i + 1 + len > tvb:len() then
                len = tvb:len() - i - 1
            end
            -- print(string.format("tvb:len(): %d, i: %d, len: %d, nPDO: %d", tvb:len(), i, len, nPDO))
            local pd_frame = tvb(i + 1, len):bytes():tvb("USB PD message")
            t:add(rxLiteralBytes, tvb(i + 1, len))
            local pd = treeitem:add(usbPDProto, pd_frame)
            i = i + len + 1
            usbPDProto.dissector(pd_frame, pinfo, pd)
        else
            local pd_frame = tvb(i + 1):bytes():tvb("USB PD message")
            t:add(rxLiteralBytes, tvb(i + 1))
            local pd = treeitem:add(usbPDProto, pd_frame)
            i = tvb:len()
            usbPDProto.dissector(pd_frame, pinfo, pd)
        end
        if i + 4 <= tvb:len() then
            t:add(rxChecksum, tvb(i, 4))
            i = i + 4
        end
    end
    return i
end

function fusb302proto.dissector(tvb, pinfo, treeitem)
    local ok, err = pcall(function()
        if prev_dissector ~= nil then
            prev_dissector:call(tvb, pinfo, treeitem)
        end
    end)
    if not ok then print(err) end

    ok, err = pcall(function()
        pinfo.cols.protocol = "FUSB302"

        local convo = getConversation()

        local isRead = i2c_flags().value % 2 > 0;

        if not pinfo.visited then
            if pinfo.number > convo.maxNum then
                convo.maxNum = pinfo.number
            end
            if isRead then
                local lastRegRead = convo:lastRequestedReg(pinfo)
                if lastRegRead == fifo_register then
                    convo.rx_chunks[pinfo.number] = tvb(1):bytes()
                elseif lastRegRead == 0x41 and bit.band(tvb(1, 1):uint(), 0x20) > 0 then
                    -- RX_EMPTY
                    convo.rx_breaks[pinfo.number] = true
                end
            else
                local reg_addr = tvb(1, 1):uint()
                if tvb:len() == 2 then
                    convo.reg_read[pinfo.number] = reg_addr
                elseif tvb:len() > 2 then
                    if reg_addr == fifo_register then
                        convo.tx_chunks[pinfo.number] = tvb(2):bytes()
                    elseif reg_addr == 0x06 and bit.band(tvb(2, 1):uint(), 0x01) > 0 then
                        -- TODO: correctly parse multi-register writes
                        -- TX_START
                        convo.tx_breaks[pinfo.number] = true
                    end
                    -- TODO: handle TX_FLUSH too
                end
            end
        end

        local subtreeitem = treeitem:add(fusb302proto, tvb(1))
        if not isRead then
            subtreeitem:add_packet_field(register_name, tvb(1, 1), ENC_UTF_8 + ENC_STRING)

            local reg_addr = tvb(1, 1):uint()
            if reg_addr == fifo_register then
                if tvb:len() > 2 then
                    pinfo.cols.info = string.format("FIFO write, %d bytes", tvb:len() - 2)

                    local start = -1
                    for i = 0, pinfo.number do
                        if convo.tx_breaks[i] then
                            start = -1
                        end
                        if convo.tx_chunks[i] then
                            if start < 0 then
                                start = i
                            end
                        end
                    end
                    if start >= 0 then
                        local buf = ByteArray.new()

                        -- We've found the last break in tx sequence based on TXON bit.
                        -- But there might be inline separators too, so let's iterate
                        -- over data we have and skip any complete packets that
                        -- end before the current frame.
                        for i = start, pinfo.number - 1 do
                            if convo.tx_chunks[i] then
                                buf:append(convo.tx_chunks[i])
                            end
                        end
                        local lastEOP = -1
                        local skip_until = -1
                        for i = 0, buf:len() - 1 do
                            if i >= skip_until then
                                local b = buf:get_index(i)
                                if b == 0xFE or b == 0x14 or bit.band(b, 0xE1) == 0xA1 then
                                    -- TXOFF, EOP, or TXON
                                    lastEOP = i
                                elseif bit.band(b, 0xE0) == 0x80 then
                                    -- PACKSYM
                                    skip_until = i + bit.band(b, 0x1F)
                                end
                            end
                        end
                        if lastEOP == buf:len() - 1 then
                            -- All previous packets were completed, we're at a start of a new one.
                            buf = ByteArray.new()
                        elseif lastEOP >= 0 then
                            buf = buf:subset(lastEOP, buf:len() - lastEOP)
                        end

                        -- Append the data from current frame.
                        buf:append(tvb(2):bytes())
                        local curFrameEnd = buf:len()

                        -- Append chunks up to the next break.
                        for i = pinfo.number + 1, convo.maxNum - 1 do
                            if convo.tx_breaks[i] then
                                break
                            elseif convo.tx_chunks[i] then
                                buf:append(convo.tx_chunks[i])
                            end
                        end

                        -- Find the first end of packet after the current frame,
                        -- and trim the tail.
                        local eop = -1
                        skip_until = -1
                        for i = 0, buf:len() - 1 do
                            if i >= skip_until then
                                local b = buf:get_index(i)
                                if b == 0xFE or b == 0x14 or bit.band(b, 0xE1) == 0xA1 then
                                    -- TXOFF, EOP or TXON
                                    eop = i
                                    if i >= curFrameEnd - 1 then
                                        break
                                    end
                                elseif bit.band(b, 0xE0) == 0x80 then
                                    -- PACKSYM
                                    skip_until = i + bit.band(b, 0x1F)
                                end
                            end
                        end
                        if eop >= 0 then
                            -- Include immediately following separators too, just so packet length remains consistent across all frames.
                            for i = eop, buf:len() - 1 do
                                local b = buf:get_index(i)
                                if b == 0xFE or b == 0x14 or bit.band(b, 0xE1) == 0xA1 then
                                    eop = i
                                else
                                    break
                                end
                            end
                            if buf:len() > eop + 1 then
                                buf = buf:subset(0, eop + 1)
                            end
                        else
                            -- Checking for incomplete packets might be important later.
                        end

                        local frame = buf:tvb("TX FIFO byte sequence")
                        subtreeitem:add(txProto, frame)
                        annotateTxBuf(frame, pinfo, treeitem)
                    end
                else
                    pinfo.cols.info = string.format("Starting FIFO read")
                end
            else
                local regname = register_names[reg_addr]
                if regname ~= nil then
                    if tvb:len() == 2 then
                        pinfo.cols.info = string.format("Request %s", regname)
                    else
                        local s = annotateRegisterValue(subtreeitem, tvb(2, 1), reg_addr)
                        pinfo.cols.info = string.format("Writing to %s: %s", regname, s)
                    end
                end
            end
        else
            local lastRegRead = convo:lastRequestedReg(pinfo)

            if lastRegRead == fifo_register then
                pinfo.cols.info = string.format("FIFO read, %d bytes", tvb:len() - 1)

                -- Here the logic is a lot simpler than on TX path, because
                -- we only treat RX_EMPTY flag as a separator.
                local start = -1
                for i = 0, pinfo.number do
                    if convo.rx_breaks[i] then
                        start = -1
                    end
                    if convo.rx_chunks[i] then
                        if start < 0 then
                            start = i
                        end
                    end
                end
                if start >= 0 then
                    local buf = ByteArray.new()
                    for i = start, convo.maxNum - 1 do
                        if convo.rx_chunks[i] then
                            buf:append(convo.rx_chunks[i])
                        end
                        if convo.rx_breaks[i] then
                            break
                        end
                    end
                    local frame = buf:tvb("RX FIFO byte sequence")
                    subtreeitem:add(rxProto, frame)
                    annotateRxBuf(frame, pinfo, treeitem)
                end
            elseif lastRegRead ~= nil and register_names[lastRegRead] ~= nil then
                -- TODO: loop over other bytes too
                local s = annotateRegisterValue(subtreeitem, tvb(1, 1), lastRegRead)
                pinfo.cols.info = string.format("%s: %s", register_names[lastRegRead], s)
            end
        end
    end)
    if not ok then print(err) end
end

DissectorTable.get("i2c.message"):add_for_decode_as(fusb302proto)

-- i2c.addr table is provided by a third-party plugin, so it might be missing.
local addrTable = DissectorTable.get("i2c.addr")
if addrTable then
    addrTable:add_for_decode_as(fusb302proto)
    addrTable:add(0x22, fusb302proto)
end


local Struct = {}
function Struct.new(s)
    s = s or {}
    setmetatable(s, Struct)
    Struct.__index = Struct
    s.usedBits = 0
    s.headerField = ProtoField.bytes(s.prefix, s.name)
    s.fields = {}
    s.fieldType = ftypes.BYTES
    if s.size == 16 then
        s.fieldType = ftypes.UINT16
    elseif s.size == 32 then
        s.fieldType = ftypes.UINT32
    end
    return s
end

function Struct:skip(n)
    self.usedBits = self.usedBits + n
end

function Struct:field(size, name, displayName, values, displayFunc)
    if self.usedBits + size > self.size then
        error(string.format("field of size %d exceeds struct bounds", size))
        return
    end

    local field = {
        size = size,
        start = self.usedBits,
        mask = bit.lshift(bit.lshift(1, size) - 1, self.usedBits),
        displayFunc = displayFunc,
    }
    self.usedBits = self.usedBits + size
    field.field = ProtoField.new(displayName or "unspecified", string.format("%s.%s", self.prefix, name),
        self.fieldType, values, base.HEX, field.mask)
    field.getter = function(tvb)
        return bit.rshift(bit.band(tvb():le_uint(), field.mask), field.start)
    end
    table.insert(self.fields, field)
    return field.getter
end

function Struct:all_fields()
    local r = { self.headerField }
    for i, f in ipairs(self.fields) do
        table.insert(r, f.field)
    end
    return r
end

function Struct:annotate(tvb, treeitem)
    local t = treeitem:add(self.headerField, tvb())

    for i, f in ipairs(self.fields) do
        print(i, f)
        local st = t:add_packet_field(f.field, tvb, ENC_LITTLE_ENDIAN)
        if f.displayFunc then
            st:append_text(" " .. f.displayFunc(f.getter(tvb)))
        end
    end

    if self.description then
        t:set_text(self.name .. ": " .. self.description(tvb))
    end
end

local pdHeaderStruct = Struct.new {
    prefix = "usb_pd.header",
    name = "Message header",
    size = 16,
}
pdHeaderStruct.getMessageType = pdHeaderStruct:field(5, "message_type")
pdHeaderStruct:skip(7)
pdHeaderStruct.getNumDataObjects = pdHeaderStruct:field(3, "num_data_objects")
pdHeaderStruct.getExtended = pdHeaderStruct:field(1, "extended")

local pdControlHeaderStruct = Struct.new {
    prefix = "usb_pd.control_message_header",
    name = "Message header",
    size = 16,
}
pdControlHeaderStruct:field(5, "message_type", "Message type",
    {
        [0] = "Reserved",
        [1] = "GoodCRC",
        [2] = "GotoMin",
        [3] = "Accept",
        [4] = "Reject",
        [5] = "Ping",
        [6] = "PS_RDY",
        [7] = "Get_Source_Cap",
        [8] = "Get_Sink_Cap",
        [9] = "DR_Swap",
        [10] = "PR_Swap",
        [11] = "VCONN_Swap",
        [12] = "Wait",
        [13] = "Soft_Reset",
        [14] = "Data_Reset",
        [15] = "Data_Reset_Complete",
        [16] = "Not_Supported",
        [17] = "Get_Source_Cap_Extended",
        [18] = "Get_Status",
        [19] = "FR_Swap",
        [20] = "Get_PPS_Status",
        [21] = "Get_Country_Codes",
        [22] = "Get_Sink_Cap_Extended",
        [23] = "Get_Source_Info",
        [24] = "Get_Revision",
    })
pdControlHeaderStruct:field(1, "port_data_role", "Port data role",
    { [0] = "Upstream-facing port", [1] = "Downstream-facing port" })
pdControlHeaderStruct:field(2, "spec_revision", "Spec revision",
    { [0] = "1.0", [1] = "2.0", [2] = "3.0", [3] = "Reserved" })
pdControlHeaderStruct:field(1, "port_power_role", "Port power role",
    { [0] = "Sink", [1] = "Source" })
pdControlHeaderStruct:field(3, "message_id", "Message ID")
pdControlHeaderStruct:field(3, "num_data_objects", "Number of data objects")
pdControlHeaderStruct:field(1, "extended", "Extended message")


local pdDataHeaderStruct = Struct.new {
    prefix = "usb_pd.data_message_header",
    name = "Message header",
    size = 16,
}
pdDataHeaderStruct:field(5, "message_type", "Message type",
    {
        [0] = "Reserved",
        [1] = "Source_Capabilities",
        [2] = "Request",
        [3] = "BIST",
        [4] = "Sink_Capabilities",
        [5] = "Battery_Status",
        [6] = "Alert",
        [7] = "Get_Country_Info",
        [8] = "Enter_USB",
        [9] = "EPR_Request",
        [10] = "EPR_Mode",
        [11] = "Source_Info",
        [12] = "Revision",
        [15] = "Vendor_Defined",
    })
pdDataHeaderStruct:field(1, "port_data_role", "Port data role",
    { [0] = "Upstream-facing port", [1] = "Downstream-facing port" })
pdDataHeaderStruct:field(2, "spec_revision", "Spec revision",
    { [0] = "1.0", [1] = "2.0", [2] = "3.0", [3] = "Reserved" })
pdDataHeaderStruct:field(1, "port_power_role", "Port power role",
    { [0] = "Sink", [1] = "Source" })
pdDataHeaderStruct:field(3, "message_id", "Message ID")
pdDataHeaderStruct:field(3, "num_data_objects", "Number of data objects")
pdDataHeaderStruct:field(1, "extended", "Extended message")

local pdPDO = Struct.new {
    prefix = "usb_pd.pdo",
    name = "PDO",
    size = 32,
}
pdPDO:skip(28)
pdPDO.getAugmentedType = pdPDO:field(2, "augmented_type", "Augmented type (only valid for APDO)",
    {
        [0] = "SPR Programmable Power Supply",
        [1] = "EPR Adjustable Voltage Supply",
        [2] = "SPR Adjustable Voltage Supply",
        [3] = "Reserved",
    })
pdPDO.getType = pdPDO:field(2, "type", "Type",
    {
        [0] = "Fixed supply",
        [1] = "Battery",
        [2] = "Variable supply (non-battery)",
        [3] = "Augmented PDO",
    })

local pdFixedPDO = Struct.new {
    prefix = "usb_pd.pdo.fixed",
    name = "PDO: Fixed supply",
    size = 32,
}
pdFixedPDO.getMaxCurrent = pdFixedPDO:field(10, "max_current", "Max current", nil,
    function(v) return string.format("%.1fA", v / 100) end)
pdFixedPDO.getVoltage = pdFixedPDO:field(10, "voltage", "Voltage", nil,
    function(v) return string.format("%.1fV", v * 50 / 1000) end)
pdFixedPDO:field(2, "peak_current", "Peak current")
pdFixedPDO:skip(1)
pdFixedPDO:field(1, "epr_mode", "EPR mode capable")
pdFixedPDO:field(1, "unchunked_extended_messages", "Unchunked Extended Messages supported")
pdFixedPDO:field(1, "drd", "Dual-role Data")
pdFixedPDO:field(1, "usb_communication", "USB Communication capable")
pdFixedPDO:field(1, "unconstrained", "Unconstrained power")
pdFixedPDO:field(1, "suspend", "USB Suspend supported")
pdFixedPDO:field(1, "drp", "Dual-role Power")
pdFixedPDO:field(2, "type", "Type",
    {
        [0] = "Fixed supply",
        [1] = "Battery",
        [2] = "Variable supply (non-battery)",
        [3] = "Augmented PDO",
    })
function pdFixedPDO.description(tvb)
    local v = pdFixedPDO.getVoltage(tvb) * 50 / 1000
    local a = pdFixedPDO.getMaxCurrent(tvb) / 100
    return string.format("%.1fV %.1fA", v, a)
end

local pdSPRPPRAPDO = Struct.new {
    prefix = "usb_pd.pdo.augmented.spr_pps",
    name = "APDO: SPR PPS",
    size = 32,
}
pdSPRPPRAPDO.getMaxCurrent = pdSPRPPRAPDO:field(7, "max_current", "Max current", nil,
    function(v) return string.format("%.1fA", v * 50 / 1000) end)
pdSPRPPRAPDO:skip(1)
pdSPRPPRAPDO.getMinVoltage = pdSPRPPRAPDO:field(8, "min_voltage", "Min voltage", nil,
    function(v) return string.format("%.1fV", v * 100 / 1000) end)
pdSPRPPRAPDO:skip(1)
pdSPRPPRAPDO.getMaxVoltage = pdSPRPPRAPDO:field(8, "max_voltage", "Max voltage", nil,
    function(v) return string.format("%.1fV", v * 100 / 1000) end)
pdSPRPPRAPDO:skip(2)
pdSPRPPRAPDO:field(1, "pps_power_limited", "PPS Power Limited")
pdSPRPPRAPDO:field(2, "augmented_type", "Augmented type",
    {
        [0] = "SPR Programmable Power Supply",
        [1] = "EPR Adjustable Voltage Supply",
        [2] = "SPR Adjustable Voltage Supply",
        [3] = "Reserved",
    })
pdSPRPPRAPDO:field(2, "type", "Type",
    {
        [0] = "Fixed supply",
        [1] = "Battery",
        [2] = "Variable supply (non-battery)",
        [3] = "Augmented PDO",
    })
function pdSPRPPRAPDO.description(tvb)
    local a = pdSPRPPRAPDO.getMaxCurrent(tvb) * 50 / 1000
    local min_v = pdSPRPPRAPDO.getMinVoltage(tvb) * 100 / 1000
    local max_v = pdSPRPPRAPDO.getMaxVoltage(tvb) * 100 / 1000
    return string.format("%.1f-%.1fV %.1fA", min_v, max_v, a)
end

local pdRequest = Struct.new {
    prefix = "usb_pd.request",
    name = "Request",
    size = 32,
}
pdRequest:field(10, "max_operating_current", "Fixed: Max operating current", nil,
    function(v) return string.format("%.1fA", v / 100) end)
pdRequest.getCurrent = pdRequest:field(10, "operating_current", "Fixed: Operating current", nil,
    function(v) return string.format("%.1fA", v / 100) end)
pdRequest:skip(2)
pdRequest:field(1, "epr_mode", "EPR mode capable")
pdRequest:field(1, "unchunked_extended_messages", "Unchunked Extended Messages supported")
pdRequest:field(1, "no_suspend", "No USB Suspend")
pdRequest:field(1, "usb_communication", "USB Communication capable")
pdRequest:field(1, "capability_mismatch", "Capability mismatch")
pdRequest:field(1, "give_back", "GiveBack flag")
pdRequest.getPDOIndex = pdRequest:field(4, "pdo_index", "Object position (1-based PDO index)")
function pdRequest.description(tvb)
    local a = pdRequest.getCurrent(tvb) / 100
    return string.format("PDO #%d @ %.1fA", pdRequest.getPDOIndex(tvb), a)
end

local pdFields = {}
for i, s in ipairs({
    pdControlHeaderStruct,
    pdDataHeaderStruct,
    pdPDO, pdFixedPDO, pdSPRPPRAPDO,
    pdRequest,
}) do
    for i, f in ipairs(s:all_fields()) do
        table.insert(pdFields, f)
    end
end
usbPDProto.fields = pdFields

local pdDataMessageType = Field.new("usb_pd.data_message_header.message_type")
function pdDataHeaderStruct.description(tvb)
    return pdDataMessageType().display
end

function usbPDProto.dissector(tvb, pinfo, treeitem)
    if tvb:len() < 2 then
        return
    end
    local headerBuf = tvb(0, 2)
    local numDataObjects = pdHeaderStruct.getNumDataObjects(headerBuf)
    local messageType = pdHeaderStruct.getMessageType(headerBuf)
    local extended = pdHeaderStruct.getExtended(headerBuf) ~= 0

    if numDataObjects == 0 then
        pdControlHeaderStruct:annotate(headerBuf, treeitem)
    else
        pdDataHeaderStruct:annotate(headerBuf, treeitem)
    end

    if not extended then
        if numDataObjects > 0 then
            for i = 0, numDataObjects - 1 do
                if 2 + i * 4 + 4 > tvb:len() then break end
                local pdo = tvb(2 + i * 4, 4)

                if messageType == 1 or messageType == 4 then
                    -- Source_Capabilities or Sink_Capabilities
                    local pdoType = pdPDO.getType(pdo)
                    local apdoType = pdPDO.getAugmentedType(pdo)
                    if pdoType == 0 then
                        pdFixedPDO:annotate(pdo, treeitem)
                    elseif pdoType == 3 and apdoType == 0 then
                        pdSPRPPRAPDO:annotate(pdo, treeitem)
                    else
                        pdPDO:annotate(pdo, treeitem)
                    end
                elseif messageType == 2 then
                    -- TODO: layout depends on the type of PDO being requested,
                    -- so we need to find the Capabilities message and locate
                    -- the PDO by index.
                    pdRequest:annotate(pdo, treeitem)
                end
            end
        end
    end
end
