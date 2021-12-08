const std = @import("std");
const allocator = std.mem.Allocator;
const ws = std.os.windows.ws2_32;

pub const debug = @import("debug.zig");

pub fn main() anyerror!void {
    _ = try std.os.windows.WSAStartup(2, 2);
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    var TLShandle: usize = try initTLS("wikipedia.org", &gpa.allocator);
    _ = TLShandle;
    _ = try std.os.windows.WSACleanup();
}

const packetType = enum {
    ServerHelloDone,
    ServerHello,
    Certificate,
    ChangeCipherSpec,
    ServerKey,
    Undefined,
};

const TLSpacket = struct {
    buffer: []u8,
    filled: usize,
    type: packetType,
};

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
    }
    std.log.debug("Created socket", .{});
    

    if (ws.connect(sock, @ptrCast(*const ws.sockaddr, res.*.addr), @intCast(i32, res.*.addrlen)) != 0) {
        std.log.err("Connection to {s} on port {s} failed!", .{hostname, port});
        return error.connectFailed;
    }
    std.log.debug("Connected to {s} on port {s}", .{hostname, port});

    var request: []u8 = try createClientHello(alloc);
    debug.showMem(request, "Generated packet");
    if (ws.send(sock, @ptrCast([*]const u8, &request[0]), @intCast(i32, request.len), 0) == ws.SOCKET_ERROR) {
        std.log.err("Error while sending: {d}", .{ws.WSAGetLastError()});
        return error.sendFailed;
    }
    std.log.debug("Sent packet", .{});
    alloc.free(request);

    var answer: TLSpacket = undefined;
    while (answer.type != packetType.ServerHelloDone) {
        answer = try tlsRecievePacket(sock, alloc);
        std.log.debug("Recieved {any}", .{answer.type});
        debug.showMem(answer.buffer[0..answer.filled], "Packet contents");
        alloc.free(answer.buffer);
    }
    // return dummy number for now ha
    return 0;
}

/// Recieves TCP packet from socket
/// Allocates packet buffer of needed size
/// packet buffer needs to be freed manualy
/// Use only if server closes connection after sending data
pub fn tlsRecievePacket(sock: ws.SOCKET, alloc: *std.mem.Allocator) anyerror!TLSpacket {
    const bufsize = 512;
    var buffer: []u8 = try alloc.alloc(u8, bufsize);
    var recv: i32 = undefined;
    var recieved: usize = 0;
    recv = ws.recv(sock, @ptrCast([*]u8, &buffer[recieved]), bufsize, ws.MSG_PEEK);
    if (recv == 0) return error.Connection_Closed;
    if (recv == -1) return error.recv_failed;
    // Handle packet type
    switch (buffer[0]) {
        // Alert packet
        0x15 => {
            std.debug.print("error: Recieved packet is an alert! (", .{});
            switch(buffer[5]) {
                1 => std.debug.print("warning)\n", .{}),
                2 => std.debug.print("fatal)\n", .{}),
                else => unreachable,
            }
            std.debug.print("error: alert description is \"", .{});
            switch(buffer[6]){
                0   => std.debug.print("Close notify", .{}),
                10  => std.debug.print("Unexpected message", .{}),
                20  => std.debug.print("Bad record MAC", .{}),
                21  => std.debug.print("Decryption failed", .{}),
                22  => std.debug.print("Record overflow", .{}),
                30  => std.debug.print("Decompression failure", .{}),
                40  => std.debug.print("Handshake failure", .{}),
                41  => std.debug.print("No certificate", .{}),
                42  => std.debug.print("Bad certificate", .{}),
                43  => std.debug.print("Unsupported certificate", .{}),
                44  => std.debug.print("Certificate revoked", .{}),
                45  => std.debug.print("Certificate expired", .{}),
                46  => std.debug.print("Certificate unknown", .{}),
                47  => std.debug.print("Illegal parameter", .{}),
                48  => std.debug.print("Unknown CA (Certificate authority)", .{}),
                49  => std.debug.print("Access denied", .{}),
                50  => std.debug.print("Decode error", .{}),
                51  => std.debug.print("Decrypt error", .{}),
                60  => std.debug.print("Export restriction", .{}),
                70  => std.debug.print("Protocol version", .{}),
                71  => std.debug.print("Insufficient security", .{}),
                80  => std.debug.print("Internal error", .{}),
                86  => std.debug.print("Inappropriate fallback", .{}),
                90  => std.debug.print("User canceled", .{}),
                100 => std.debug.print("No renegotiation ", .{}),
                110 => std.debug.print("Unsupported extension", .{}),
                111 => std.debug.print("Certificate unobtainable", .{}),
                112 => std.debug.print("Unrecognized name", .{}),
                113 => std.debug.print("Bad certificate status response", .{}),
                114 => std.debug.print("Bad certificate hash value", .{}),
                115 => std.debug.print("Unknown PSK identity (used in TLS-PSK and TLS-SRP)", .{}),
                else => unreachable,
            }
            std.debug.print("\"\n", .{});
            // alloc.free(buffer);
            // return error.recievedAlert;
        },
        // Handshake packet
        0x16 => //std.log.debug("recieved handshake record", .{}),
        {},
        // Data packet
        0x17 => {
            std.log.debug("recieved application data", .{});
            // return recieved packet as slice
            return error.Cannot_Handle_Packet_Type;
        },
        // ChangeCipherSpec packet
        0x14 => {
            std.log.debug("recieved ChangeCipherSpec", .{});
            // return recieved packet as slice
            return error.Cannot_Handle_Packet_Type;
        },
        // Heartbeat packet
        0x18 => {
            std.log.debug("recieved ChangeCipherSpec", .{});
            // return error?
            return error.Cannot_Handle_Packet_Type;
        },
        else => {
            std.log.err("recieved non-TLS data", .{});
            unreachable;
        }
    }

    // Handle protocol version
    var version: u16 = @intCast(u16, buffer[2]) | @intCast(u16, buffer[1]) << 8;
    switch (version) {
        0x0300 => return error.SSL30_is_unsupported,
        0x0301 => return error.TLS10_is_unsupported,
        0x0302 => return error.TLS11_is_unsupported,
        0x0303 => {},
        0x0304 => return error.TLS13_is_unsupported,
        else => unreachable,
    }

    var packet_size: u16 = (@intCast(u16, buffer[4]) | @intCast(u16, buffer[3]) << 8) + 5;
    while (true) {
        // Make sure buffer can fit all the data
        if (buffer.len < recieved + bufsize) buffer = try alloc.realloc(buffer, buffer.len + bufsize);
        var to_recieve: i32 = if (recieved + bufsize > packet_size) @intCast(i32, packet_size - recieved) else bufsize;
        recv = ws.recv(sock, @ptrCast([*]u8, &buffer[recieved]), to_recieve, 0);
        if (recv == 0) return error.Connection_Closed;
        if (recv == -1) return error.recv_failed;
        recieved += @intCast(usize, recv);
        if (recieved >= packet_size) return TLSpacket {
            .buffer = buffer,
            .filled = packet_size,
            .type = switch (buffer[5]) {
                0x02 => packetType.ServerHello,
                0x0B => packetType.Certificate,
                0x0C => packetType.ServerKey,
                0x0E => packetType.ServerHelloDone,
                else => packetType.Undefined,
            }
        };
    }
}



pub fn createClientHello(alloc: *std.mem.Allocator) anyerror![]u8 {
    // Lengths
    const essentials_len: usize = 44;
    var cipher_suites_len: usize = 0;
    var compressions_len: usize = 0;
    var extensions_len: usize = 0;
    var filled: usize = 0;
    // Packet type is handshake
    var data = try alloc.alloc(u8, essentials_len);
    data[filled] = 0x16;
    filled += 1;
    // TLS version
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, 0x0301));
    filled += 2;
    // allocate space for folowing bytes count
    filled += 2;

    // Handshake Header
    // Handshake type code is client hello
    data[filled] = 0x01;
    filled += 1;
    // allocate space for following bytes count
    filled += 3;

    // Client Version
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, 0x0303));
    filled += 2;

    // Client Random
    var rng = std.rand.DefaultPrng.init(@intCast(u64, std.time.timestamp()));
    for (data[filled..data.len]) |*pointer| {
        pointer.* = rng.random.int(u8);
    }
    filled += 32;

    // Session ID
    data[filled] = 0x00;
    filled += 1;

    // Cipher Suites
    const cipher_suites = [_]u16 {
        0xcca8, 0xcca9, 0xc02f, 0xc030,
        0xc030, 0xc02b, 0xc02c, 0xc013
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
    // Size of compression algos
    data[filled] = 0x01;
    filled += 1;
    // Compression algos
    // 0 == none
    data[filled] = 0x00;
    filled += 1;

    // Extensions
    // allocate space for extensions size
    data = try alloc.realloc(data, filled + 2);
    filled += 2;

    // var extension_server_name: []u8 = (try debug.hexStringToSlice(alloc, "0000000F000D00000A676f6f676c652e636f6d"));
    // data = try alloc.realloc(data, filled + extension_server_name.len);
    // std.mem.copy(u8, data[filled..filled+extension_server_name.len], extension_server_name);
    // filled += extension_server_name.len;
    // alloc.free(extension_server_name);
    // extensions_len += extension_server_name.len;

    // var extension_status_request: []u8 = (try debug.hexStringToSlice(alloc, "000500050100000000"));
    // data = try alloc.realloc(data, filled + extension_status_request.len);
    // std.mem.copy(u8, data[filled..filled+extension_status_request.len], extension_status_request);
    // filled += extension_status_request.len;
    // alloc.free(extension_status_request);
    // extensions_len += extension_status_request.len;

    var extension_supported_groups: []u8 = (try debug.hexStringToSlice(alloc, "000a000a0008001d001700180019"));
    data = try alloc.realloc(data, filled + extension_supported_groups.len);
    std.mem.copy(u8, data[filled..filled+extension_supported_groups.len], extension_supported_groups);
    filled += extension_supported_groups.len;
    alloc.free(extension_supported_groups);
    extensions_len += extension_supported_groups.len;

    // Filling sizes
    // Record Header
    std.mem.copy(u8, data[3..5], intToBytes(u16, @intCast(u16, data.len-5)));
    // Handshake Header
    std.mem.copy(u8, data[5..9], intToBytes(u32, @intCast(u32, data.len-5-4) & 0x00ffffff | @intCast(u32, data[5]) << @intCast(std.math.Log2Int(u32),3*8)));
    // Extensions Length
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
