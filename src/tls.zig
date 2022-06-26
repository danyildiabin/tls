const std = @import("std");
const debug = @import("debug.zig");
const utility = @import("utility.zig");
const enums = @import("enums.zig");
const structs = @import("structs.zig");
const ecc = @import("ecc.zig");

const ws = std.os.windows.ws2_32;
const bigInt = std.math.big.int.Managed;
const rand = std.crypto.random;

/// Will be returning proper TLS session interface in future
/// Inits a handshake on port 433, Windows only
pub fn initTLS(hostname: [*:0]const u8, alloc: std.mem.Allocator) anyerror!usize {
    const port = "443";
    var hints: ws.addrinfo = .{
        .flags = 0,
        .family = ws.AF.UNSPEC,
        .socktype = ws.SOCK.STREAM,
        .protocol = ws.IPPROTO.TCP,
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
        std.log.err("socket creation failed", .{});
        return error.socketCreationFailed;
    } else {
        std.log.debug("created socket", .{});
    }

    if (ws.connect(sock, @ptrCast(*const ws.sockaddr, res.*.addr), @intCast(i32, res.*.addrlen)) != 0) {
        std.log.err("connection to {s} on port {s} failed!", .{ hostname, port });
        return error.connectFailed;
    } else {
        std.log.debug("connected to {s} on port {s}", .{ hostname, port });
    }

    // allocate storage for keys
    var server_random = try alloc.alloc(u8, 32);
    defer alloc.free(server_random);
    var client_random = try alloc.alloc(u8, 32);
    defer alloc.free(client_random);
    var server_public_key_x = try alloc.alloc(u8, 32);
    defer alloc.free(server_public_key_x);
    var server_public_key_y = try alloc.alloc(u8, 32);
    defer alloc.free(server_public_key_y);
    var client_private_key = try alloc.alloc(u8, 32);
    defer alloc.free(client_private_key);

    // start handshake
    var client_hello = try createClientHello(alloc);
    defer alloc.free(client_hello.data);
    try debug.printRecord(client_hello, "sent to server");
    try sendRecord(alloc, sock, client_hello);

    std.mem.copy(u8, client_random, client_hello.data[6 .. 6 + 32]);

    // recieve server answer records
    while (true) {
        var answer = try recieveRecord(sock, alloc);
        defer alloc.free(answer.data);
        try debug.printRecord(answer, "recieved from server");
        if (answer.type != enums.ContentType.handshake) return error.non_handshake_packet_during_handshake;
        var handshake_type = @intToEnum(enums.HandshakeType, answer.data[0]);
        switch (handshake_type) {
            .server_hello => {
                std.mem.copy(u8, server_random, answer.data[6 .. 6 + 32]);
            },
            .certificate => {},
            .server_key_exchange => {
                std.mem.copy(u8, server_public_key_x, answer.data[9 .. 9 + 32]);
                std.mem.copy(u8, server_public_key_y, answer.data[9 + 32 .. 9 + 64]);
            },
            .server_hello_done => {},
            .finished => {},
            .certificate_status => {},
            else => return error.unexpected_message,
        }
        if (handshake_type == enums.HandshakeType.server_hello_done) break;
    }

    // Public key generation with secp256r1 curve
    std.debug.print("===> calculating public key\n", .{});
    // temporary numbers
    var x = try bigInt.init(alloc);
    defer x.deinit();
    var y = try bigInt.init(alloc);
    defer y.deinit();
    var y_pow_2 = try bigInt.init(alloc);
    defer y_pow_2.deinit();
    var x_pow_3 = try bigInt.init(alloc);
    defer x_pow_3.deinit();
    var ax = try bigInt.init(alloc);
    defer ax.deinit();
    var result = try bigInt.init(alloc);
    defer result.deinit();
    var garbage = try bigInt.init(alloc);
    defer garbage.deinit();

    // generate random 32byte (256bit) number
    var random: bigInt = try bigInt.init(alloc);
    defer random.deinit();
    var randomdata: []u8 = try alloc.alloc(u8, 32);
    for (randomdata) |*pointer| pointer.* = rand.int(u8);
    var randomdata_string: []u8 = try std.fmt.allocPrint(alloc, "{s}", .{std.fmt.fmtSliceHexUpper(randomdata)});
    alloc.free(randomdata);
    try random.setString(16, randomdata_string);
    alloc.free(randomdata_string);

    var working_curve = try ecc.NamedCurve.init(alloc, ecc.EllipticCurve.test_curve);
    defer working_curve.deinit();

    std.log.debug("Curve parameters:", .{});
    std.log.debug("p: {d}", .{working_curve.p});
    std.log.debug("a: {d}", .{working_curve.a});
    std.log.debug("b: {d}", .{working_curve.b});
    std.log.debug("n: {d}", .{working_curve.n});
    std.log.debug("x: {d}", .{working_curve.g.x});
    std.log.debug("y: {d}", .{working_curve.g.y});

    const G = try ecc.pointDouble(alloc, working_curve, working_curve.g);
    std.log.debug("Calculated point x: {d}", .{G.x});
    std.log.debug("Calculated point y: {d}", .{G.y});
    // result on sep256r1 curve G point should be
    // x: 56515219790691171413109057904011688695424810155802929973526481321309856242040
    // y: 3377031843712258259223711451491452598088675519751548567112458094635497583569

    // //  y^2 = x^3 + ax + b
    // // Point belong to curve if (X^3 + AX + B - Y**2) % P == 0
    // // x^3 & ax
    // try bigInt.pow(&x_pow_3, x.toConst(), 3);
    // std.log.debug("run1 {}", .{x_pow_3});
    // try bigInt.mul(&ax, a.toConst(), x.toConst());
    // std.log.debug("run2 {}", .{ax});
    // // x^3 + ax
    // try bigInt.add(&result, x_pow_3.toConst(), ax.toConst());
    // std.log.debug("run3 {}", .{result});
    // // (x^3 + ax) + b
    // try bigInt.add(&result, result.toConst(), b.toConst());
    // // (x^3 + ax + b) - y^2
    // try bigInt.pow(&y_pow_2, y.toConst(), 2);
    // try bigInt.sub(&result, result.toConst(), y_pow_2.toConst());

    // try bigInt.divFloor(&garbage, &result, y_pow_2.toConst(), p.toConst());

    // std.log.debug("res: {any}", .{result});

    // // (x^3 + ax + b) % p
    // const temp_const_3 = temp_val_3.toConst();
    // var ignore: bigInt = try bigInt.init(alloc);
    // defer ignore.deinit();
    // try bigInt.divFloor(&ignore, &res_val, temp_const_3, p);

    // var test_record: structs.Record = .{
    //     .type = .handshake,
    //     .version = .TLS_1_2,
    //     .data = try utility.hexStringToSlice(alloc, "0E000000"),
    // };
    // defer alloc.free(test_record.data);
    // try debug.printRecord(test_record, "sent unexpected message");
    // try sendRecord(alloc, sock, test_record);
    // var answer2 = try recieveRecord(sock, alloc);
    // defer alloc.free(answer2.data);
    // try debug.printRecord(answer2, "recieved this");

    // debug.showMem(client_random, "Client Random");
    // debug.showMem(server_random, "Server Random");
    // debug.showMem(server_public_key_x, "Server Public Key X");
    // debug.showMem(server_public_key_y, "Server Public Key Y");
    // debug.showMem(client_private_key, "Client Private key");
    // debug.showMem(client_public_key_x, "Client Public Key X");
    // debug.showMem(client_public_key_y, "Client Public Key Y");

    // G = try ECCPointDouble(alloc, G);
    // std.debug.print("G: {any}\n", .{G});

    return 0;
}

// TODO implement proper filling from function parameters
/// Creates basic client hello
pub fn createClientHello(alloc: std.mem.Allocator) anyerror!structs.Record {
    // Lengths
    const essentials_len: usize = 38;
    var session_id_len: usize = 1;
    var ciphersuites_len: usize = 0;
    var compressions_len: usize = 0;
    var extensions_len: usize = 0;
    var filled: usize = 0;

    var result: structs.Record = .{
        .type = .handshake,
        .version = .TLS_1_0,
        .data = try alloc.alloc(u8, essentials_len),
    };
    errdefer alloc.free(result.data);

    // Handshake Header
    // Header type
    result.data[filled] = @enumToInt(enums.HandshakeType.client_hello);
    filled += 1;
    // allocate space for following bytes count
    filled += 3;

    // Client Version
    std.mem.writeIntSliceBig(u16, result.data[filled .. filled + 2], @enumToInt(enums.Version.TLS_1_2));
    filled += 2;

    // Client Random
    for (result.data[filled .. filled + 32]) |*pointer| pointer.* = rand.int(u8);
    filled += 32;

    result.data = try alloc.realloc(result.data, filled + session_id_len);
    // Session ID
    result.data[filled] = 0x00;
    filled += 1;

    // Cipher Suites
    const cipher_suites = [_]enums.CipherSuite{
        .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        // .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        // .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ciphersuites_len = 2 + cipher_suites.len * 2;
    result.data = try alloc.realloc(result.data, filled + ciphersuites_len);
    std.mem.writeIntSliceBig(u16, result.data[filled .. filled + 2], cipher_suites.len * 2);
    filled += 2;
    for (cipher_suites) |suite| {
        std.mem.writeIntSliceBig(u16, result.data[filled .. filled + 2], @enumToInt(suite));
        filled += 2;
    }

    // Compression Methods
    compressions_len += 2;
    result.data = try alloc.realloc(result.data, filled + compressions_len);
    result.data[filled] = 0x01;
    filled += 1;
    result.data[filled] = 0x00;
    filled += 1;

    // Extensions
    // allocate space for extensions size
    result.data = try alloc.realloc(result.data, filled + 2);
    filled += 2;

    var extension_server_name: []u8 = (try utility.hexStringToSlice(alloc, "0000000F000D00000A676f6f676c652e636f6d"));
    result.data = try alloc.realloc(result.data, filled + extension_server_name.len);
    std.mem.copy(u8, result.data[filled .. filled + extension_server_name.len], extension_server_name);
    filled += extension_server_name.len;
    alloc.free(extension_server_name);
    extensions_len += extension_server_name.len;

    var extension_status_request: []u8 = (try utility.hexStringToSlice(alloc, "000500050100000000"));
    result.data = try alloc.realloc(result.data, filled + extension_status_request.len);
    std.mem.copy(u8, result.data[filled .. filled + extension_status_request.len], extension_status_request);
    filled += extension_status_request.len;
    alloc.free(extension_status_request);
    extensions_len += extension_status_request.len;

    var extension_supported_groups: []u8 = (try utility.hexStringToSlice(alloc, "000a000400020017"));
    result.data = try alloc.realloc(result.data, filled + extension_supported_groups.len);
    std.mem.copy(u8, result.data[filled .. filled + extension_supported_groups.len], extension_supported_groups);
    filled += extension_supported_groups.len;
    alloc.free(extension_supported_groups);
    extensions_len += extension_supported_groups.len;

    var extension_supported_formats: []u8 = (try utility.hexStringToSlice(alloc, "000B00020100"));
    result.data = try alloc.realloc(result.data, filled + extension_supported_formats.len);
    std.mem.copy(u8, result.data[filled .. filled + extension_supported_formats.len], extension_supported_formats);
    filled += extension_supported_formats.len;
    alloc.free(extension_supported_formats);
    extensions_len += extension_supported_formats.len;

    // Set size for handshake header
    result.data[1] = 0;
    std.mem.writeIntSliceBig(u16, result.data[2..4], @intCast(u16, result.data.len - 4));
    // Set size for extensions header
    const offset = essentials_len + ciphersuites_len + compressions_len + session_id_len;
    std.mem.writeIntSliceBig(u16, result.data[offset .. offset + 2], @intCast(u16, extensions_len));
    return result;
}

/// Recieves TLS record from socket
/// Result.data must be freed manualy
pub fn recieveRecord(sock: ws.SOCKET, alloc: std.mem.Allocator) anyerror!structs.Record {
    const recv_bufsize = 1024;
    var recv_buffer: []u8 = try alloc.alloc(u8, recv_bufsize);
    defer alloc.free(recv_buffer);
    var recv: i32 = ws.recv(sock, recv_buffer.ptr, @intCast(i32, recv_bufsize), ws.MSG.PEEK);
    if (recv == -1) return error.RecvFailed;
    if (recv == 0) return error.ConnectionClosed;

    var packet_size = (@intCast(u16, recv_buffer[4]) | @intCast(u16, recv_buffer[3]) << 8);
    var result: structs.Record = .{
        .type = @intToEnum(enums.ContentType, recv_buffer[0]),
        .version = @intToEnum(enums.Version, (@intCast(u16, recv_buffer[2]) | @intCast(u16, recv_buffer[1]) << 8)),
        .data = try alloc.alloc(u8, packet_size),
    };
    errdefer alloc.free(result.data);

    // flush 5 bytes of record header to recieve record data in loop
    recv = ws.recv(sock, @ptrCast([*]u8, &result.data[0]), 5, 0);
    if (recv == -1) return error.RecvFailed;
    if (recv == 0) return error.ConnectionClosed;

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

/// Sends TLS record from socket
/// Result.data must be freed manualy
pub fn sendRecord(alloc: std.mem.Allocator, sock: ws.SOCKET, record: structs.Record) anyerror!void {
    var send_buffer = try alloc.alloc(u8, 5);
    defer alloc.free(send_buffer);
    send_buffer[0] = @enumToInt(record.type);
    std.mem.writeIntSliceBig(u16, send_buffer[1..3], @enumToInt(record.version));
    std.mem.writeIntSliceBig(u16, send_buffer[3..5], @intCast(u16, record.data.len));

    var res: i32 = ws.send(sock, send_buffer.ptr, 5, 0);
    if (res == -1) return error.SendFailed;
    if (res == 0) return error.ConnectionClosed;

    res = ws.send(sock, record.data.ptr, @intCast(i32, record.data.len), 0);
    if (res == -1) return error.SendFailed;
    if (res == 0) return error.ConnectionClosed;
}
