const std = @import("std");
const debug = @import("debug.zig");
const tls = @import("constants.zig");

const allocator = std.mem.Allocator;
const ws = std.os.windows.ws2_32;

pub fn main() anyerror!void {
    _ = try std.os.windows.WSAStartup(2, 2);
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    var TLShandle: usize = initTLS("google.com", &gpa.allocator) catch 0;
    _ = TLShandle;
    _ = try std.os.windows.WSACleanup();
}

pub fn initTLS(hostname: [*:0]const u8, alloc: *std.mem.Allocator) anyerror!usize {
    const port = "443";
    var hints: ws.addrinfo = .{
        .flags = 0,
        .family = ws.AF_UNSPEC,
        .socktype = ws.SOCK_STREAM,
        .protocol = ws.IPPROTO_TCP,
        .addrlen = 0,
        .canonname = null,
        .addr = null,
        .next = null,
    };
    var res: *ws.addrinfo = undefined;
    _ = ws.getaddrinfo(hostname, port, &hints, &res);

    var sock: ws.SOCKET = ws.socket(res.*.family, res.*.socktype, res.*.protocol);
    defer _ = ws.closesocket(sock);

    if (sock == ws.INVALID_SOCKET) {
        std.log.err("Socket creation failed", .{});
        return error.socketCreationFailed;
    } else {
        std.log.debug("Created socket", .{});
    }

    if (ws.connect(sock, @ptrCast(*const ws.sockaddr, res.*.addr), @intCast(i32, res.*.addrlen)) != 0) {
        std.log.err("Connection to {s} on port {s} failed!", .{hostname, port});
        return error.connectFailed;
    } else {
        std.log.debug("Connected to {s} on port {s}", .{hostname, port});
    }

    var request: []u8 = try createClientHello(alloc);
    defer alloc.free(request);
    debug.showMem(request, "Generated packet");
    if (ws.send(sock, @ptrCast([*]const u8, &request[0]), @intCast(i32, request.len), 0) == ws.SOCKET_ERROR) {
        std.log.err("Error while sending: {d}", .{ws.WSAGetLastError()});
        return error.sendFailed;
    } else {
        std.log.debug("Sent packet", .{});
    }

    var answer: tls.Record = undefined;
    while (true) {
        answer = try tlsRecievePacket(sock, alloc);
        defer alloc.free(answer.data);
        std.log.debug("Recieved {any}", .{answer.type});
        debug.showMem(answer.data, "Packet contents");
        if (@intToEnum(tls.HandshakeType, answer.data[5]) == tls.HandshakeType.server_hello_done) break;
    }
    return 0;
}

/// Recieves TCP packet from socket
/// Allocates packet buffer of needed size
/// packet buffer needs to be freed manualy
/// Use only if server closes connection after sending data
pub fn tlsRecievePacket(sock: ws.SOCKET, alloc: *std.mem.Allocator) anyerror!tls.Record {
    var result: tls.Record = undefined;
    const recv_bufsize = 1024;
    var recv_buffer: []u8 = try alloc.alloc(u8, recv_bufsize);
    defer alloc.free(recv_buffer);
    var recv: i32 = ws.recv(sock, recv_buffer.ptr, @intCast(i32, recv_bufsize), ws.MSG_PEEK);
    if (recv == -1) return error.RecvFailed;
    if (recv == 0) return error.ConnectionClosed;

    result.type = @intToEnum(tls.ContentType, recv_buffer[0]);
    // Handle packet type
    switch (result.type) {
        .alert => {
            var alert_level: tls.AlertLevel = @intToEnum(tls.AlertLevel, recv_buffer[5]);
            var alert_description: tls.AlertDescription = @intToEnum(tls.AlertDescription, recv_buffer[6]);
            switch (alert_level) {
                .warning => {
                    std.log.warn("Recieved a warning alert! {any}", .{alert_description});
                    return error.recieved_warning_alert;
                };
                .fatal => {
                    std.log.warn("Recieved a fatal alert! {any}", .{alert_description});
                    return error.recieved_fatal_alert;
                };
                else => return error.unrecognized_alert_level
            }
        },
        .handshake => {std.log.debug("handshake type is {any}", .{@intToEnum(tls.HandshakeType, recv_buffer[5])});},
        else => {
            std.log.err("Recieved {any}", .{result.type});
            return error.unrecognized_content_type;
        }
    }

    // Handle protocol version
    result.version = @intToEnum(tls.Version, (@intCast(u16, recv_buffer[2]) | @intCast(u16, recv_buffer[1]) << 8));
    switch (result.version) {
        .TLS_1_2 => {},
        else => return error.unrecognized_tls_version,
    }

    var packet_size: u16 = (@intCast(u16, recv_buffer[4]) | @intCast(u16, recv_buffer[3]) << 8) + 5;
    result.data = try alloc.alloc(u8, packet_size);
    errdefer alloc.free(result.data);
    var recieved: usize = 0;
    while (true) {
        // Set smaller buffer if need to recieve less than default buffersize
        var to_recieve: usize = if (packet_size - recieved < recv_bufsize) (packet_size - recieved) else recv_bufsize;

        recv = ws.recv(sock, @ptrCast([*]u8, &result.data[recieved]), @intCast(i32, to_recieve), 0);
        if (recv == -1) return error.RecvFailed;
        if (recv == 0) return error.ConnectionClosed;
        recieved += @intCast(usize, recv);
        if (recieved == packet_size) break;
    }
    return result;
}



pub fn createClientHello(alloc: *std.mem.Allocator) anyerror![]u8 {
    // Lengths
    const essentials_len: usize = 44;
    var cipher_suites_len: usize = 0;
    var compressions_len: usize = 0;
    var extensions_len: usize = 0;
    var filled: usize = 0;

    // Record Header
    // Record type
    var data = try alloc.alloc(u8, essentials_len);
    errdefer alloc.free(data);
    data[filled] = @enumToInt(tls.ContentType.handshake);
    filled += 1;
    // TLS version
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, 0x0301));
    filled += 2;
    // Allocate space size header
    filled += 2;

    // Handshake Header
    // Header type
    data[filled] = @enumToInt(tls.HandshakeType.client_hello);
    filled += 1;
    // allocate space for following bytes count
    filled += 3;

    // Client Version
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, 0x0303));
    filled += 2;

    // Client Random
    var rng = std.rand.DefaultPrng.init(@intCast(u64, std.time.timestamp()));
    for (data[filled..data.len]) |*pointer| pointer.* = rng.random.int(u8);
    filled += 32;

    // Session ID
    data[filled] = 0x00;
    filled += 1;

    // Cipher Suites
    const cipher_suites = [_]u16 {
        0xcca8, 0xcca9, 0xc02f, 0xc030,
        0xc030, 0xc02b, 0xc02c, 0xc013,
    };
    cipher_suites_len = 2 + cipher_suites.len * 2;
    data = try alloc.realloc(data, filled + cipher_suites_len);
    std.mem.copy(u8, data[filled..filled+2], intToBytes(u16, @intCast(u16, cipher_suites.len*2)));
    filled += 2;
    for (cipher_suites) |suite| {
        std.mem.copy(u8, data[filled..filled+2], intToBytes(u16, suite));
        filled += 2;
    }

    // Compression Methods
    compressions_len += 2;
    data = try alloc.realloc(data, filled + compressions_len);
    data[filled] = 0x01;
    filled += 1;
    data[filled] = 0x00;
    filled += 1;

    // Extensions
    // allocate space for extensions size
    data = try alloc.realloc(data, filled + 2);
    filled += 2;

    var extension_server_name: []u8 = (try debug.hexStringToSlice(alloc, "0000000F000D00000A676f6f676c652e636f6d"));
    data = try alloc.realloc(data, filled + extension_server_name.len);
    std.mem.copy(u8, data[filled..filled+extension_server_name.len], extension_server_name);
    filled += extension_server_name.len;
    alloc.free(extension_server_name);
    extensions_len += extension_server_name.len;

    var extension_status_request: []u8 = (try debug.hexStringToSlice(alloc, "000500050100000000"));
    data = try alloc.realloc(data, filled + extension_status_request.len);
    std.mem.copy(u8, data[filled..filled+extension_status_request.len], extension_status_request);
    filled += extension_status_request.len;
    alloc.free(extension_status_request);
    extensions_len += extension_status_request.len;

    var extension_supported_groups: []u8 = (try debug.hexStringToSlice(alloc, "000a000a0008001d001700180019"));
    data = try alloc.realloc(data, filled + extension_supported_groups.len);
    std.mem.copy(u8, data[filled..filled+extension_supported_groups.len], extension_supported_groups);
    filled += extension_supported_groups.len;
    alloc.free(extension_supported_groups);
    extensions_len += extension_supported_groups.len;
    
    // Set size for record header
    std.mem.copy(u8, data[3..5], intToBytes(u16, @intCast(u16, data.len-5)));
    // Set size for handshake header
    std.mem.copy(u8, data[5..9], intToBytes(u32, @intCast(u32, data.len-5-4) & 0x00ffffff | @intCast(u32, data[5]) << @intCast(std.math.Log2Int(u32),3*8)));
    // Set size for extensions header
    std.mem.copy(u8, data[essentials_len+cipher_suites_len+compressions_len..essentials_len+cipher_suites_len+compressions_len+2], intToBytes(u16, @intCast(u16, extensions_len)));
    return data;
}

pub fn intToBytes(comptime T: type, num: T) []u8 {
    var i: usize = 0;
    var result: [@sizeOf(T)]u8 = undefined;
    while (i < @sizeOf(T)) : (i += 1) {
        result[(@sizeOf(T)-1)-i] = @intCast(u8, (num >> @intCast(std.math.Log2Int(T), i*8)) & 0xFF);
    }
    return result[0..];
}
