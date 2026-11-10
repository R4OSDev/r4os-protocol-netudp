const r4os = @import("r4os");
const ipv6 = @import("ipv6.zig");

const IPV4_PROTOCOL: u8 = 17;
const HEADER_SIZE: usize = 8;

comptime {
    if (!@import("builtin").is_test) asm (r4os.technical2.protocolEntriesAsm("netudp_init", "netudp_shutdown", "netudp_query", "netudp_dispatch"));
}

export fn netudp_init(api: *const r4os.abi.ProtocolApi2) callconv(.c) i32 {
    const view = r4os.technical2.Protocol.init(api) orelse return r4os.abi.network_error_backend;
    const register = view.function("register_role") orelse return r4os.abi.err_no_fn;
    const status = view.function("set_status") orelse return r4os.abi.err_no_fn;
    ipv6.init(api) catch |err| return r4os.network_transport.common.code(err);
    if (register("net.udp", @intFromEnum(r4os.abi.ProtocolCategory.net), 0) != 0) {
        ipv6.stop();
        return r4os.abi.network_error_backend;
    }
    const result = status(@intFromEnum(r4os.abi.ProtocolState.active), "UDP IPv4 codec and external IPv6 transport");
    if (result != 0) ipv6.stop();
    return result;
}

export fn netudp_shutdown() callconv(.c) i32 {
    ipv6.stop();
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
    if (op >= r4os.abi.network_op_info) return ipv6.dispatch(op, in_buffer, out_buffer);
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.udp_op_handle_rx => inspect(request, (in_buffer.flags & r4os.abi.protocol_buffer_flag_rx_l4_checksum_valid) != 0),
        r4os.abi.udp_op_handle_tx => inspect(request, false),
        r4os.abi.udp_op_build_datagram => buildDatagram(request),
        else => return -4,
    }
    return request.result;
}

fn inspect(request: *r4os.abi.UdpOp, l4_checksum_valid: bool) void {
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
    if (!l4_checksum_valid and checksum_field != 0 and checksum(request.source_ip, request.dest_ip, packet) != 0) {
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
    const native = r4os.native_protocol_view;
    var policy = native.Policy.record(r4os.abi.UdpOp, .inout, .prefix);
    // This flag only admits the existing trusted RX metadata; the operation
    // still decides whether it may skip its wire checksum. TX never does.
    policy.allowed_flags = r4os.abi.protocol_buffer_flag_rx_l4_checksum_valid;
    var metadata = buffer.*;
    const view = native.InOut(r4os.abi.UdpOp).init(&metadata, policy) catch return null;
    return view.value;
}

fn checksum(source_ip: [4]u8, dest_ip: [4]u8, udp: []const u8) u16 {
    // The protocol retains pseudoheader composition and UDP zero policy.
    var header: [4]u8 = .{ 0, IPV4_PROTOCOL, 0, 0 };
    var writer = r4os.binary_cursor.Writer.init(&header) catch unreachable;
    writer.position = 2;
    writer.writeInt(u16, @intCast(udp.len), .big) catch unreachable;
    var value: r4os.internet_checksum.Checksum16 = .{};
    value.add(&source_ip) catch unreachable;
    value.add(&dest_ip) catch unreachable;
    value.add(&header) catch unreachable;
    value.add(udp) catch unreachable;
    return value.finish() catch unreachable;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    var reader = r4os.binary_cursor.Reader.init(buf) catch unreachable;
    _ = reader.take(offset) catch unreachable;
    return reader.readInt(u16, .big) catch unreachable;
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    var writer = r4os.binary_cursor.Writer.init(buf) catch unreachable;
    writer.position = offset;
    writer.writeInt(u16, value, .big) catch unreachable;
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
