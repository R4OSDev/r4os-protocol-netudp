//! Real IPv6 UDP sockets. The existing service owns the public front handles.
const std = @import("std");
const sdk = @import("r4os");
const t = sdk.network_transport;
const a = sdk.abi;
const Error = t.Error;
const queued = 4;
const Datagram = struct { source: a.NetworkEndpoint = .{}, length: u16 = 0, data: [1496]u8 = @splat(0) };
const Socket = struct {
    used: bool = false,
    generation: u64 = 0,
    broker: a.ProgramProcessHandle = .{},
    owner: a.ProgramProcessHandle = .{},
    endpoint: a.NetworkEndpoint = .{},
    link_provider: u64 = 0,
    link_generation: u64 = 0,
    head: u8 = 0,
    count: u8 = 0,
    queue: [queued]Datagram = @splat(.{}),
};
var runtime: ?t.Runtime = null;
var sockets: [16]Socket = @splat(.{});
var next_generation: u64 = 1;
var next_port: u16 = 49152;

pub fn init(raw: *const a.ProtocolApi2) Error!void {
    runtime = try t.Runtime.init(raw);
    sockets = @splat(.{});
    next_generation = 1;
    next_port = 49152;
}
pub fn stop() void {
    sockets = @splat(.{});
    runtime = null;
}
fn matches(socket: *const Socket, endpoint: a.NetworkEndpoint) bool {
    return socket.endpoint.port == endpoint.port and socket.endpoint.address.interface_id == endpoint.address.interface_id and (t.zero(socket.endpoint.address) or t.zero(endpoint.address) or t.sameAddress(socket.endpoint.address, endpoint.address));
}
fn available(endpoint: a.NetworkEndpoint) bool {
    for (&sockets) |*socket| if (socket.used and matches(socket, endpoint)) return false;
    return true;
}
fn sweep(r: t.Runtime) void {
    for (&sockets) |*socket| {
        if (!socket.used) continue;
        if (r.gone(socket.broker) or r.gone(socket.owner)) socket.* = .{};
    }
}
fn tick(r: t.Runtime) Error!void {
    sweep(r);
    var index: u32 = 0;
    while (index < 8) : (index += 1) {
        const info = r.rpc(a.Ipv6InterfaceQuery, a.Ipv6InterfaceInfo, "net.ipv6", a.ipv6_op_info, .{ .index = index }) catch |err| {
            if (err == error.NotFound) continue;
            return err;
        };
        for (&sockets) |*socket| if (socket.used and socket.endpoint.address.interface_id == info.link.interface_id and (socket.link_generation != info.link.generation or socket.link_provider != info.link.provider or info.capabilities == 0)) {
            socket.* = .{};
        };
        var budget: u32 = 0;
        while (budget < 16) : (budget += 1) {
            const packet = r.receive(info, 17) catch |err| {
                if (err == error.WouldBlock or err == error.UnsupportedPolicy) break;
                return err;
            };
            if (packet.bytes < 8 or packet.bytes > packet.payload.len) continue;
            const bytes = packet.payload[0..packet.bytes];
            const length = t.read16(bytes, 4);
            if (length < 8 or length > bytes.len or t.read16(bytes, 6) == 0) continue;
            const destination: a.NetworkEndpoint = .{ .address = packet.destination, .port = t.read16(bytes, 2) };
            for (&sockets) |*socket| {
                if (!socket.used or !matches(socket, destination)) continue;
                // UDP overflow drops the new datagram. An unread packet is
                // never overwritten or replaced by a later arrival.
                if (socket.count == queued) break;
                const entry = &socket.queue[(@as(usize, socket.head) + socket.count) % queued];
                entry.* = .{ .source = .{ .address = packet.source, .port = t.read16(bytes, 0) }, .length = length - 8 };
                @memcpy(entry.data[0..entry.length], bytes[8..length]);
                socket.count += 1;
                break;
            }
        }
    }
}
fn lookup(value: a.NetworkTransportRequest) Error!*Socket {
    const req = value.request;
    if (req.socket == 0 or req.socket > sockets.len or req.generation == 0) return error.BadSocket;
    const socket = &sockets[@intCast(req.socket - 1)];
    if (!socket.used or socket.generation != req.generation or !t.sameProcess(socket.broker, value.broker) or !t.sameProcess(socket.owner, value.owner)) return error.BadSocket;
    return socket;
}
fn result(value: a.NetworkTransportRequest, socket: *const Socket, id: u64) a.NetworkSocketResult {
    return .{ .provider = value.provider, .socket = id, .generation = socket.generation, .endpoint = socket.endpoint, .state = a.network_state_ready };
}
fn dispatchInner(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) Error!void {
    const r = runtime orelse return error.Backend;
    if (op == a.network_op_info) {
        if (input.flags != 0 or input.reserved != 0 or input.len != 0 or output.flags != 0 or output.reserved != 0) return error.Invalid;
        var info: a.NetworkProviderInfo = .{ .provider = (try r.identity()).provider };
        if (r.interface(0)) |link| {
            info.capabilities = a.network_cap_ipv6 | a.network_cap_udp | a.network_cap_datagram_truncate;
            info.interface_id = link.link.interface_id;
            info.max_send = 1232;
            info.max_recv = 1496;
        } else |err| if (err != error.NotFound and err != error.UnsupportedPolicy) return err;
        return t.put(a.NetworkProviderInfo, &info, "", output);
    }
    const native = sdk.native_protocol_view;
    var input_policy = native.Policy.versioned(a.NetworkTransportRequest, 1, .input, .prefix);
    input_policy.alignment = 1; // the existing copied header + payload transport
    _ = native.admit(input, input_policy, .input) catch return error.Invalid;
    const value = try r.decodeRequest(input, output);
    const req = value.request;
    if (req.flags != 0) return error.UnsupportedPolicy;
    const sending = op == a.network_op_send;
    if (input.len != @sizeOf(a.NetworkTransportRequest) + @as(usize, if (sending) req.bytes else 0)) return error.Invalid;
    if (!sending and op != a.network_op_recv and req.bytes != 0) return error.Invalid;
    var output_policy = native.Policy.record(a.NetworkSocketResult, .output, .prefix);
    output_policy.alignment = 1;
    _ = native.admit(output, output_policy, .output) catch return error.Capacity;
    if (op == a.network_transport_op_tick) {
        if (req.socket != 0 or req.generation != 0) return error.Invalid;
        try tick(r);
        const reply: a.NetworkSocketResult = .{ .provider = value.provider, .state = a.network_state_ready };
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    try tick(r);
    if (op == a.network_op_bind) {
        if (!t.common.ownerAlive(r, value.owner)) return error.BadSocket;
        if (req.socket != 0 or req.generation != 0) return error.Invalid;
        if (req.endpoint.address.family != 6) return error.UnsupportedFamily;
        const info = try r.interface(req.endpoint.address.interface_id);
        var endpoint = req.endpoint;
        endpoint.address.interface_id = info.link.interface_id;
        const ll = endpoint.address.bytes[0] == 0xfe and endpoint.address.bytes[1] & 0xc0 == 0x80;
        if (ll and endpoint.address.scope_id != info.link.interface_id or !ll and endpoint.address.scope_id != 0) return error.UnsupportedScope;
        if (!t.zero(endpoint.address)) {
            // Let the IPv6 owner validate that this exact source is local.
            _ = try r.prepare(endpoint.address, info.link_local, 17, req.deadline);
        }
        if (endpoint.port == 0) {
            var attempts: u32 = 0;
            while (attempts < 16384) : (attempts += 1) {
                endpoint.port = next_port;
                next_port = if (next_port == 65535) 49152 else next_port + 1;
                if (available(endpoint)) break;
            }
            if (!available(endpoint)) return error.Capacity;
        } else if (!available(endpoint)) return error.Capacity;
        if (next_generation == std.math.maxInt(u64)) return error.Capacity;
        for (&sockets, 0..) |*socket, index| if (!socket.used) {
            socket.* = .{ .used = true, .generation = next_generation, .broker = value.broker, .owner = value.owner, .endpoint = endpoint, .link_provider = info.link.provider, .link_generation = info.link.generation };
            next_generation += 1;
            const reply = result(value, socket, index + 1);
            return t.put(a.NetworkSocketResult, &reply, "", output);
        };
        return error.Capacity;
    }
    const socket = try lookup(value);
    var reply = result(value, socket, req.socket);
    if (op == a.network_op_close) {
        try t.put(a.NetworkSocketResult, &reply, "", output);
        socket.* = .{};
        return;
    }
    if (sending) {
        if (req.bytes > 1232 or req.endpoint.port == 0) return if (req.bytes > 1232) error.PacketTooBig else error.Invalid;
        var packet = try r.prepare(socket.endpoint.address, req.endpoint.address, 17, req.deadline);
        if (packet.provider != socket.link_provider or packet.generation != socket.link_generation) return error.ProviderChanged;
        packet.bytes = req.bytes + 8;
        t.write16(&packet.payload, 0, socket.endpoint.port);
        t.write16(&packet.payload, 2, req.endpoint.port);
        t.write16(&packet.payload, 4, @intCast(packet.bytes));
        const payload: [*]const u8 = @ptrCast(input.data.?);
        @memcpy(packet.payload[8..packet.bytes], payload[@sizeOf(a.NetworkTransportRequest)..input.len]);
        try r.checksum(&packet, 6);
        try r.send(packet);
        reply.endpoint = .{ .address = packet.source, .port = socket.endpoint.port };
        reply.bytes = req.bytes;
        reply.original_bytes = req.bytes;
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    if (op == a.network_op_recv) {
        if (socket.count == 0) return error.WouldBlock;
        const entry = &socket.queue[socket.head];
        const amount = @min(req.bytes, entry.length);
        reply.endpoint = entry.source;
        reply.bytes = amount;
        reply.original_bytes = entry.length;
        reply.flags = if (amount < entry.length) a.network_flag_truncated else 0;
        try t.put(a.NetworkSocketResult, &reply, entry.data[0..amount], output);
        entry.* = .{};
        socket.head = (socket.head + 1) % queued;
        socket.count -= 1;
        return;
    }
    return error.UnsupportedPolicy;
}
pub fn dispatch(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) i32 {
    dispatchInner(op, input, output) catch |err| return t.common.code(err);
    return 0;
}
