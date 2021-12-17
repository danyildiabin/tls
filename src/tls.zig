const std = @import("std");
const debug = @import("debug.zig");
const utility = @import("utility.zig");
const ws = std.os.windows.ws2_32;

/// Recieves TCP packet from socket
/// Allocates packet buffer of needed size
/// packet buffer needs to be freed manualy
/// Use only if server closes connection after sending data
pub fn recieveRecord(sock: ws.SOCKET, alloc: *std.mem.Allocator) anyerror!Record {
    var result: Record = undefined;
    const recv_bufsize = 1024;
    var recv_buffer: []u8 = try alloc.alloc(u8, recv_bufsize);
    defer alloc.free(recv_buffer);
    var recv: i32 = ws.recv(sock, recv_buffer.ptr, @intCast(i32, recv_bufsize), ws.MSG_PEEK);
    if (recv == -1) return error.RecvFailed;
    if (recv == 0) return error.ConnectionClosed;

    result.type = @intToEnum(ContentType, recv_buffer[0]);
    result.version = @intToEnum(Version, (@intCast(u16, recv_buffer[2]) | @intCast(u16, recv_buffer[1]) << 8));
    var packet_size = (@intCast(u16, recv_buffer[4]) | @intCast(u16, recv_buffer[3]) << 8);
    result.data = try alloc.alloc(u8, packet_size);
    errdefer alloc.free(result.data);
    
    // flush 5 bytes of record header to recieve data only in loop
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

pub fn sendRecord(alloc: *std.mem.Allocator, sock: ws.SOCKET, record: Record) anyerror!void {
    var send_buffer = try alloc.alloc(u8, 5);
    defer alloc.free(send_buffer);
    send_buffer[0] = @enumToInt(record.type);
    std.mem.writeIntSliceBig(u16, send_buffer[1..3], @enumToInt(record.version));
    std.mem.writeIntSliceBig(u16, send_buffer[3..5], @intCast(u16, record.data.len));

    var res: i32 = ws.send(sock, send_buffer.ptr, 5, 0);
    if (res == -1) return error.SendFailed;
    if (res == 0) return error.ConnectionClosed;

    debug.showMem(record.data[0..record.data.len], "about to send this shit");

    res = ws.send(sock, record.data.ptr, @intCast(i32, record.data.len), 0);
    if (res == -1) return error.SendFailed;
    if (res == 0) return error.ConnectionClosed;
}

pub fn parseHandshakeRecord(data: []u8) anyerror!HandshakeHeader {
    // TODO use all 3 bytes for size calculation
    var size = @intCast(u16, recv_buffer[3]) | @intCast(u16, recv_buffer[2]) << 8;
    if (size >= (0xFFFF-5)) return error.decode_error_bad_message_size;
    return struct {
        type: @intToEnum(HandshakeType, data[0]),
        data: data[4..],
    };
}

pub fn parseClientHello(data: []u8) anyerror!ClientHelloRecord {
    var result: ClientHelloRecord = undefined;
    var reading: usize = 0;
    result.version = @intToEnum(Version, (@intCast(u16, data[reading+1]) | @intCast(u16, data[reading]) << 8));
    reading += 2;
    result.client_random = data[reading..reading+32];
    reading += 32;
    std.log.debug("{X:0>2}", .{data[reading]});
    if (data[reading] == 0) {
        result.session_id = null;
        reading += 1;
    } else {
        result.session_id = data[reading+1..reading+1+data[reading]];
        reading += (1+data[reading]);
    }
    var cipher_count = @intCast(u16, data[reading+1]) | @intCast(u16, data[reading]) << 8;
    result.cipher_suites = @ptrCast([*]u16, @alignCast(@alignOf([*]u16), data[reading+2..reading+2+cipher_count*2]))[0..cipher_count];
    reading += (2+cipher_count*2);
    if (data[reading] == 1 and data[reading+1] == 0) {
        result.compression_methods = null;
        reading += 2;
    } else {
        result.compression_methods = data[reading+1..reading+1+data[reading]];
        reading += (1+data[reading]);
    }
    result.extensions = null;
    return result;
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
        std.log.err("socket creation failed", .{});
        return error.socketCreationFailed;
    } else {
        std.log.debug("created socket", .{});
    }

    if (ws.connect(sock, @ptrCast(*const ws.sockaddr, res.*.addr), @intCast(i32, res.*.addrlen)) != 0) {
        std.log.err("connection to {s} on port {s} failed!", .{hostname, port});
        return error.connectFailed;
    } else {
        std.log.debug("connected to {s} on port {s}", .{hostname, port});
    }

    var request: []u8 = try createClientHello(alloc);
    defer alloc.free(request);
    debug.showMem(request, "generated packet");
    // var hello_record: ClientHelloRecord = try parseClientHello(request[5+4..request.len]);
    // std.log.debug("{}", .{hello_record});
    if (ws.send(sock, @ptrCast([*]const u8, &request[0]), @intCast(i32, request.len), 0) == ws.SOCKET_ERROR) {
        std.log.err("srror while sending: {d}", .{ws.WSAGetLastError()});
        return error.sendFailed;
    } else {
        std.log.debug("sent client_hello", .{});
    }

    var answer: Record = undefined;
    // recieve server answer records
    while (true) {
        answer = try recieveRecord(sock, alloc);
        defer alloc.free(answer.data);
        if (answer.type != ContentType.handshake) return error.non_handshake_packet_during_handshake;
        var handshake_type = @intToEnum(HandshakeType, answer.data[0]);
        std.log.debug("recieved {}", .{handshake_type});
        debug.showMem(answer.data[0..answer.data.len], "packet contents");
        switch (handshake_type) {
            .server_hello => {},
            .certificate => {},
            .server_key_exchange => {},
            .server_hello_done => {},
            .finished => {},
            else => return error.unexpected_message,
        }
        if (handshake_type == HandshakeType.server_hello_done) break;
    }
    var test_record: Record = .{
        .type = .handshake,
        .version = .TLS_1_2,
        .data = try debug.hexStringToSlice(alloc, "0E000000"),
    };
    defer alloc.free(test_record.data);
    try sendRecord(alloc, sock, test_record);
    var answer2 = try recieveRecord(sock, alloc);
    defer alloc.free(answer2.data);
    std.log.debug("{}", .{answer2});
    return 0;
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
    data[filled] = @enumToInt(ContentType.handshake);
    filled += 1;
    // TLS version
    std.mem.writeIntSliceBig(u16, data[filled..filled+2], 0x0301);
    filled += 2;
    // Allocate space size header
    filled += 2;

    // Handshake Header
    // Header type
    data[filled] = @enumToInt(HandshakeType.client_hello);
    filled += 1;
    // allocate space for following bytes count
    filled += 3;

    // Client Version
    std.mem.writeIntSliceBig(u16, data[filled..filled+2], 0x0303);
    filled += 2;

    // Client Random
    var rng = std.rand.DefaultPrng.init(@intCast(u64, std.time.timestamp()));
    for (data[filled..data.len]) |*pointer| pointer.* = rng.random.int(u8);
    filled += 32;

    // Session ID
    data[filled] = 0x00;
    filled += 1;

    // Cipher Suites
    const cipher_suites = [_]CipherSuite {
        .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        // .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        // .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    cipher_suites_len = 2 + cipher_suites.len * 2;
    data = try alloc.realloc(data, filled + cipher_suites_len);
    std.mem.writeIntSliceBig(u16, data[filled..filled+2], cipher_suites.len*2);
    filled += 2;
    for (cipher_suites) |suite| {
        std.mem.writeIntSliceBig(u16, data[filled..filled+2], @enumToInt(suite));
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

    // var extension_status_request: []u8 = (try debug.hexStringToSlice(alloc, "000500050100000000"));
    // data = try alloc.realloc(data, filled + extension_status_request.len);
    // std.mem.copy(u8, data[filled..filled+extension_status_request.len], extension_status_request);
    // filled += extension_status_request.len;
    // alloc.free(extension_status_request);
    // extensions_len += extension_status_request.len;

    var extension_supported_groups: []u8 = (try debug.hexStringToSlice(alloc, "000a000400020017"));
    data = try alloc.realloc(data, filled + extension_supported_groups.len);
    std.mem.copy(u8, data[filled..filled+extension_supported_groups.len], extension_supported_groups);
    filled += extension_supported_groups.len;
    alloc.free(extension_supported_groups);
    extensions_len += extension_supported_groups.len;
    
    // Set size for record header
    std.mem.writeIntSliceBig(u16, data[3..5], @intCast(u16, data.len-5));
    // Set size for handshake header
    data[6] = 0;
    std.mem.writeIntSliceBig(u16, data[7..9], @intCast(u16, data.len-5-4));
    // Set size for extensions header
    const offset = essentials_len + cipher_suites_len + compressions_len;
    std.mem.writeIntSliceBig(u16, data[offset..offset+2], @intCast(u16, extensions_len));
    return data;
}

/////////////////////////
// STRUCT DECLARATIONS //
/////////////////////////

pub const handshakeHeader = struct {
    type: HandshakeType,
    data: []u8,
};

pub const ClientHelloRecord = struct {
    version: Version,
    client_random: []u8,
    session_id: ?[]u8,
    cipher_suites: []u16,
    compression_methods: ?[]u8,
    extensions: ?[]Extension,
};

pub const Record = struct {
    type: ContentType,
    version: Version,
    data: []u8,
};

pub const Client = struct {
    cipher: u16,
    session_id: Version,
    compression: []u8,
};

pub const Extension = struct {
    type: ExtensionType,
    data: []u8,
};

pub const ECCPublicKey = struct {
    compressed_y: CompressedY,
    point_x: []u8,
};

///////////////////////
// ENUM DECLARATIONS //
///////////////////////

pub const ContentType = enum (u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
    _,
};

pub const CompressedY = enum (u8) {
    even = 2,
    odd = 3,
    _,
};

// Formated as IANA names
// PROTOCOL KEY_EXCHANGE_ALGORITHM DIGITAL_SIGNATURE_ALGORITHM BULK_ENCRYPTION_ALGORITHM HASHING_ALGORITHM
// List defined here are approved TLS 1.2 Ciphers according to
// https://comodosslstore.com/resources/ssl-cipher-suites-ultimate-guide/
// kinda cringe, I know
// 
// ECDHE - Elliptic Curve Diffie-Hellman Ephemeral
// ECDSA - Elliptic Curve Digital Signature Algorithm
// GCM - Galois/Counter mode
// AES - Advanced encryption standard 
// SHA - Secure Hash Algorithm
// CBC - Cipher Block Chaining
// RSA - Rivest Shamir Adleman algorithm
pub const CipherSuite = enum (u16) {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,       // Recommended
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,       // Recommended
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,       // Weak
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,       // Weak
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,         // Secure
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,         // Secure
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,         // Weak
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,         // Weak
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,           // Secure
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,           // Secure
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,              // Weak
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,              // Weak
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,           // Weak
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,           // Weak
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9, // Recommended
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,   // Secure
    _,
};

pub const ExtensionType = enum (u16) {
    server_name = 0,
    _,
};

pub const AlertLevel = enum (u8) {
    warning = 1,
    fatal = 2,
    _,
};
 
pub const AlertDescription = enum (u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,
};

pub const HandshakeType = enum (u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange  = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_status = 22,
    key_update = 24,
    message_hash = 254,
    _,
};

pub const Version = enum (u16) {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304,
    _,
};

pub const EllipticCurve = enum (u16) {
    sect163k1 = 0x0001,
    sect163r1 = 0x0002,
    sect163r2 = 0x0003,
    sect193r1 = 0x0004,
    sect193r2 = 0x0005,
    sect233k1 = 0x0006,
    sect233r1 = 0x0007,
    sect239k1 = 0x0008,
    sect283k1 = 0x0009,
    sect283r1 = 0x000A,
    sect409k1 = 0x000B,
    sect409r1 = 0x000C,
    sect571k1 = 0x000D,
    sect571r1 = 0x000E,
    secp160k1 = 0x000F,
    secp160r1 = 0x0010,
    secp160r2 = 0x0011,
    secp192k1 = 0x0012,
    secp192r1 = 0x0013,
    secp224k1 = 0x0014,
    secp224r1 = 0x0015,
    secp256k1 = 0x0016,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    _,
};
