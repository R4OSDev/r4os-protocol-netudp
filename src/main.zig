const r4os = @import("r4os");

const IPV4_PROTOCOL: u8 = 17;
const HEADER_SIZE: usize = 8;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("netudp_init", "netudp_shutdown", "netudp_query", "netudp_dispatch"));
}

export fn netudp_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("NETUDP.R4P init");
    _ = ctx.registerRole("net.udp", .net, 0);
    _ = ctx.setStatus(.active, "UDP R4P active");
    return 0;
}

export fn netudp_shutdown() callconv(.c) i32 {
    return 0;
}

export fn netudp_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("UDP R4P ready"),
    };
    return 0;
}

export fn netudp_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.udp_op_handle_rx => inspect(request),
        r4os.abi.udp_op_handle_tx => inspect(request),
        r4os.abi.udp_op_build_datagram => buildDatagram(request),
        else => return -4,
    }
    return request.result;
}

fn inspect(request: *r4os.abi.UdpOp) void {
    request.payload_len = 0;
    if (request.datagram_len < HEADER_SIZE or request.datagram_len > request.datagram.len) {
        request.result = r4os.abi.udp_result_short;
        return;
    }
    const datagram = request.datagram[0..@intCast(request.datagram_len)];
    const udp_len = readBe16(datagram, 4);
    if (udp_len < HEADER_SIZE or datagram.len < udp_len) {
        request.result = r4os.abi.udp_result_length;
        return;
    }
    const packet = datagram[0..udp_len];
    const checksum_field = readBe16(packet, 6);
    if (checksum_field != 0 and checksum(request.source_ip, request.dest_ip, packet) != 0) {
        request.result = r4os.abi.udp_result_checksum;
        return;
    }
    request.source_port = readBe16(packet, 0);
    request.dest_port = readBe16(packet, 2);
    request.length = udp_len;
    const payload = packet[HEADER_SIZE..];
    request.payload_len = @intCast(payload.len);
    if (payload.len > 0) @memcpy(request.payload[0..payload.len], payload);
    request.result = r4os.abi.udp_result_ok;
}

fn buildDatagram(request: *r4os.abi.UdpOp) void {
    const len = HEADER_SIZE + @as(usize, @intCast(request.payload_len));
    if (request.payload_len > request.payload.len or len > 0xFFFF or request.datagram.len < len) {
        request.result = r4os.abi.udp_result_buffer_small;
        return;
    }
    writeBe16(request.datagram[0..], 0, request.source_port);
    writeBe16(request.datagram[0..], 2, request.dest_port);
    writeBe16(request.datagram[0..], 4, @intCast(len));
    writeBe16(request.datagram[0..], 6, 0);
    var i: usize = 0;
    const payload_len: usize = @intCast(request.payload_len);
    while (i < payload_len) : (i += 1) request.datagram[HEADER_SIZE + i] = request.payload[i];
    var sum = checksum(request.source_ip, request.dest_ip, request.datagram[0..len]);
    if (sum == 0) sum = 0xFFFF;
    writeBe16(request.datagram[0..], 6, sum);
    request.datagram_len = @intCast(len);
    request.length = @intCast(len);
    request.result = r4os.abi.udp_result_ok;
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.UdpOp {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.UdpOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn checksum(source_ip: [4]u8, dest_ip: [4]u8, udp: []const u8) u16 {
    var sum: u32 = 0;
    sum = addIp(sum, source_ip);
    sum = addIp(sum, dest_ip);
    sum += IPV4_PROTOCOL;
    sum += @intCast(udp.len);
    var i: usize = 0;
    while (i + 1 < udp.len) : (i += 2) {
        sum += (@as(u32, udp[i]) << 8) | udp[i + 1];
    }
    if (i < udp.len) sum += @as(u32, udp[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

fn addIp(sum_in: u32, ip: [4]u8) u32 {
    return sum_in + (@as(u32, ip[0]) << 8 | ip[1]) + (@as(u32, ip[2]) << 8 | ip[3]);
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    return (@as(u16, buf[offset]) << 8) | buf[offset + 1];
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
