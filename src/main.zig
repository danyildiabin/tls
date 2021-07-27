const std = @import("std");
const allocator = std.mem.Allocator;
const ws = std.os.windows.ws2_32;
const hostname = "discord.com";
const port = "443";
const recieveError = error {
    ConnectionClosed,
    NoDataAvailable,
    UnknownError,
};


pub fn main() anyerror!void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    _ = try std.os.windows.WSAStartup(2, 2);

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
    } else { 
        std.log.info("Socket created", .{});
    }

    if (ws.connect(sock, @ptrCast(*const ws.sockaddr, res.*.addr), @intCast(i32, res.*.addrlen)) != 0) {
        std.log.err("Cannot connect trough TCP", .{});
    } else { 
        std.log.info("Connected to {s} on port {s}", .{hostname, port});
    }

    // var file: []u8 = openfile();
    // showMem(file, "Opened file");
    var request: []u8 = try createPacket(&gpa.allocator);
    showMem(request, "Generated packet");

    if (ws.send(sock, @ptrCast([*]const u8, &request[0]), @intCast(i32, request.len), 0) == ws.SOCKET_ERROR) {
        std.log.err("Error while sending: {d}", .{ws.WSAGetLastError()});
    } else { 
        std.log.info("Sent packet", .{});
    }
    gpa.allocator.free(request);

    var recv_buf: []u8 = try recievePacket(sock, &gpa.allocator);
    std.log.info("Recieved packet", .{});
    if (recv_buf[0] == 21) {
        std.debug.print("error: Recieved packet is an alert! (", .{});
        switch(recv_buf[5]){
            1 => std.debug.print("warning", .{}),
            2 => std.debug.print("fatal", .{}),
            else => unreachable,
        }
        std.debug.print(")\nerror: alert description is \"", .{});
        switch(recv_buf[6]){
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
    }
    showMem(recv_buf, "Packet content");
    gpa.allocator.free(recv_buf);
    _ = try std.os.windows.WSACleanup();
}

pub const timeval = extern struct {
    tv_sec: c_long,
    tv_usec: c_long,
};
pub extern "ws2_32" fn select(
    nfds: i32,
    readfds: ?*ws.fd_set,
    writefds: ?*ws.fd_set,
    exceptfds: ?*ws.fd_set,
    timeout: ?*const timeval,
) callconv(std.os.windows.WINAPI) i32;

pub fn recievePacket(sock: ws.SOCKET, alloc: *std.mem.Allocator) anyerror![]u8 {
    var fd_set: ws.fd_set = ws.fd_set {
        .fd_count = 1,
        .fd_array = undefined,
    };
    fd_set.fd_array[0] = sock;

    const time: timeval = timeval{
        .tv_sec = 1,
        .tv_usec = 0,
    };

    const bufsize = 1;
    var buffer: []u8 = try alloc.alloc(u8, bufsize);
    errdefer alloc.free(buffer);
    var recieved: usize = 0;
    var sel: i32 = undefined;
    var recv: i32 = undefined;
    var mode: u32 = 1;  // 1 to enable non-blocking socket
    _ = ws.ioctlsocket(sock, ws.FIONBIO, &mode);
    defer _ = ws.ioctlsocket(sock, ws.FIONBIO, &mode);
    defer mode = 0;
    while (true) {
        sel = select(0, &fd_set, null, null, &time);
        if (sel > 0) {
            // Make sure buffer can fit all the data
            if (buffer.len < recieved + bufsize) {
                buffer = try alloc.realloc(buffer, buffer.len + bufsize);
            }
            recv = ws.recv(sock, @ptrCast([*]u8, &buffer[recieved]), bufsize, 0);
            recieved += @intCast(usize, recv);
            if (recv == 0 and recieved == 0) return recieveError.ConnectionClosed;
            continue;
        } else if (sel == 0) {
            // Nothing changed for 1 second.
            if (recieved > 0) return buffer[0..recieved];
            return recieveError.NoDataAvailable;
        } else {
            return recieveError.UnknownError;
        }
    }
}

pub fn createPacket(alloc: *std.mem.Allocator) anyerror![]u8 {
    var filled: usize = 0;
    var data: []u8 = undefined;

    // Packet type is handshake
    data = try alloc.alloc(u8, 1);
    data[filled] = 0x16;
    filled += 1;
    // TLS version
    data = try alloc.realloc(data, filled+2);
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, 0x0301));
    filled += 2;
    // allocate space for folowing bytes count
    data = try alloc.realloc(data, filled+2);
    filled += 2;

    // Handshake Header
    // Handshake type code is client hello
    data = try alloc.realloc(data, filled+1);
    data[filled] = 0x01;
    filled += 1;
    // allocate space for following bytes count
    data = try alloc.realloc(data, filled+3);
    filled += 3;

    // Client Version
    data = try alloc.realloc(data, filled+2);
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, 0x0303));
    filled += 2;
    // Client Random
    data = try alloc.realloc(data, filled+32);
    var rng = std.rand.DefaultPrng.init(@intCast(u64, std.time.timestamp()));
    for (data[filled..data.len]) |*pointer| {
        pointer.* = rng.random.int(u8);
    }
    filled += 32;
    // Session ID
    data = try alloc.realloc(data, filled+1);
    data[filled] = 0x00;
    filled += 1;
    // Cipher Suites
    const cipher_suites = [_]u16{
        0xcca8, 0xcca9, 0xc02f, 0xc030,
        0xc02b, 0xc02c, 0xc013, 0xc009,
        0xc014, 0xc00a, 0x009c, 0x009d,
        0x002f, 0x0035, 0xc012, 0x000a,
        };
    data = try alloc.realloc(data, filled + 2 + @sizeOf(@TypeOf(cipher_suites)));
    std.mem.copy(u8, data[filled..data.len], intToBytes(u16, @sizeOf(@TypeOf(cipher_suites))));
    filled += 2;
    for (cipher_suites) |suite| {
        std.mem.copy(u8, data[filled..data.len], intToBytes(u16, suite));
        filled += 2;
    }
    // Compression Methods
    data = try alloc.realloc(data, filled+2);
    data[filled] = 0x01;
    filled += 1;
    data[filled] = 0x00;
    filled += 1;
    // Extensions Length

    // Extensions

    // Filling sizes
    // Record Header
    std.mem.copy(u8, data[3..5], intToBytes(u16, @intCast(u16, data.len-5)));
    // Handshake Header
    std.mem.copy(u8, data[5..9], intToBytes(u32, @intCast(u32, data.len-5-4) & 0x00ffffff | @intCast(u32, data[5]) << @intCast(std.math.Log2Int(u32),3*8))
    );

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

pub fn openfile() []u8 {
    var buffer: [116]u8 = undefined;
    if (std.c.fopen("C:/Users/Danyil/Development/Discord/HS Bot/zig-out/bin/packet.bin", "r")) |file| {
        _ = std.c.fread(@ptrCast([*]u8, &buffer[0]), 116, 1, file);
        std.log.info("Successfuly read packet file", .{});
    }
    return buffer[0..];
}

pub fn showMem(slice: []u8, note: []const u8) void {
    std.debug.print("debug: Examining memory \"{s}\" ({d} bytes)", .{note, slice.len});
    var i: usize = 0;
    while (i < slice.len) : (i += 1) {
        if (i % 16 == 0) {
            std.debug.print("\n{X:0>16}: ", .{@ptrToInt(&slice[i])});
        }
        std.debug.print(" {X:0>2}", .{slice[i]});
    }
    std.debug.print("\n", .{});
}