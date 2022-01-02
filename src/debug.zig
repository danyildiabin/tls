const std = @import("std");
const tls = @import("tls.zig");
const enums = @import("enums.zig");
const structs = @import("structs.zig");

pub fn printRecord(record: structs.Record, note: []const u8) anyerror!void {
    std.debug.print("\n===> {s}\n", .{note});
    std.debug.print("Type is {}\n", .{record.type});
    std.debug.print("Version is {}\n", .{record.version});
    switch (record.type) {
        .handshake => {
            const handshake_type = @intToEnum(enums.HandshakeType, record.data[0]);
            std.debug.print("Handshake type is {}\n", .{handshake_type});
            const size = @intCast(u64, record.data[1]) << 16 | @intCast(u64, record.data[2]) << 8 | @intCast(u64, record.data[3]);
            std.debug.print("Handshake size is {} bytes\n", .{size});
            var reading: usize = 4;
            switch (handshake_type) {
                .client_hello => {
                    const version = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                    reading += 2;
                    std.debug.print("Protocol version is {}\n", .{@intToEnum(enums.Version, version)});
                    std.debug.print("Client random is 0x", .{});
                    for (record.data[reading .. reading + 32]) |byte| {
                        std.debug.print("{X:0>2}", .{byte});
                    }
                    reading += 32;
                    std.debug.print("\nSession ID is ", .{});
                    if (record.data[reading] == 0) {
                        std.debug.print("not provided", .{});
                        reading += 1;
                    } else {
                        std.debug.print("0x", .{});
                        for (record.data[reading + 1 .. reading + 1 + record.data[reading]]) |byte| {
                            std.debug.print("{X:0>2}", .{byte});
                        }
                        reading += 1 + record.data[reading];
                    }
                    const ciphersuites_n = (@intCast(u16, record.data[reading]) << 8 | record.data[reading + 1]) >> 1;
                    std.debug.print("\nProposed {d} ciphersuites:\n", .{ciphersuites_n});
                    reading += 2;
                    // FIXME this function reverses byteorder of u16 to littleEndian, it should not
                    var ciphersuites = std.mem.bytesAsSlice(u16, record.data[reading .. reading + ciphersuites_n * 2]);
                    for (ciphersuites) |word| {
                        std.debug.print("{}\n", .{@intToEnum(enums.CipherSuite, ((0x00ff & word) << 8) | ((0xff00 & word) >> 8))});
                    }
                    reading += ciphersuites_n * 2;
                    // TODO add compressions enum
                    const compression_n = record.data[reading];
                    std.debug.print("Proposed {d} compression algorithms:\n", .{compression_n});
                    reading += 1;
                    for (record.data[reading .. reading + compression_n]) |byte| {
                        std.debug.print("0x{X:0>2}\n", .{byte});
                    }
                    reading += compression_n;

                    if (reading == record.data.len) {
                        std.debug.print("Extensions are not provided\n", .{});
                    } else {
                        const extensions_size = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                        std.debug.print("Extensions size is {d} bytes\n", .{extensions_size});
                        reading += 2;
                        while (true) {
                            const extension = @intToEnum(enums.ExtensionType, @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]));
                            reading += 2;
                            const extensionsize = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                            reading += 2;
                            // TODO implement something to show extension info
                            std.debug.print("Extension: {}, size is {d} bytes: ", .{ extension, extensionsize });
                            for (record.data[reading .. reading + extensionsize]) |byte| {
                                std.debug.print("{X:0>2}", .{byte});
                            }
                            std.debug.print("\n", .{});
                            reading += extensionsize;
                            if (reading == record.data.len) break;
                        }
                    }
                },
                .server_hello => {
                    const version = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                    reading += 2;
                    std.debug.print("Protocol version is {}\n", .{@intToEnum(enums.Version, version)});
                    std.debug.print("Server random is 0x", .{});
                    for (record.data[reading .. reading + 32]) |byte| {
                        std.debug.print("{X:0>2}", .{byte});
                    }
                    reading += 32;
                    std.debug.print("\nSession ID is ", .{});
                    if (record.data[reading] == 0) {
                        std.debug.print("not provided", .{});
                        reading += 1;
                    } else {
                        std.debug.print("0x", .{});
                        for (record.data[reading + 1 .. reading + 1 + record.data[reading]]) |byte| {
                            std.debug.print("{X:0>2}", .{byte});
                        }
                        reading += 1 + record.data[reading];
                    }
                    const ciphersuite = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                    std.debug.print("\nSelected ciphersuite is {}\n", .{@intToEnum(enums.CipherSuite, ciphersuite)});
                    reading += 2;
                    // TODO add compressions enum
                    std.debug.print("Selected compression method is 0x{X:0>2}\n", .{record.data[reading]});
                    reading += 1;
                    if (reading == record.data.len) {
                        std.debug.print("Extensions are not provided\n", .{});
                    } else {
                        const extensions_size = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                        std.debug.print("Extensions size is {d} bytes\n", .{extensions_size});
                        reading += 2;
                        while (true) {
                            const extension = @intToEnum(enums.ExtensionType, @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]));
                            reading += 2;
                            const extensionsize = @intCast(u16, record.data[reading]) << 8 | @intCast(u16, record.data[reading + 1]);
                            reading += 2;
                            // TODO implement something to show extension info
                            std.debug.print("Extension: {}, size is {d} bytes: ", .{ extension, extensionsize });
                            for (record.data[reading .. reading + extensionsize]) |byte| {
                                std.debug.print("{X:0>2}", .{byte});
                            }
                            std.debug.print("\n", .{});
                            reading += extensionsize;
                            if (reading == record.data.len) break;
                        }
                    }
                },
                .certificate => {
                    const combined_size: u64 = @intCast(u64, record.data[reading]) << 16 | @intCast(u64, record.data[reading + 1]) << 8 | record.data[reading + 2];
                    std.debug.print("All certificates with size headers is {d} bytes\n", .{combined_size});
                    reading += 3;
                    var certificate_n: usize = 0;
                    while (true) {
                        certificate_n += 1;
                        const cert_size: u64 = @intCast(u64, record.data[reading]) << 16 | @intCast(u64, record.data[reading + 1]) << 8 | record.data[reading + 2];
                        std.debug.print("Certificate #{d} is {d} bytes long\n", .{ certificate_n, cert_size });
                        reading += 3 + cert_size;
                        if (reading == record.data.len) break;
                    }
                },
                .server_key_exchange => {
                    const curve_type = @intToEnum(enums.ECCurveType, record.data[reading]);
                    std.debug.print("Curve type is {}\n", .{curve_type});
                    reading += 1;
                    const curve = @intToEnum(enums.EllipticCurve, @intCast(u16, record.data[reading]) << 8 | record.data[reading + 1]);
                    std.debug.print("Selected curve is {}\n", .{curve});
                    reading += 2;
                    const keysize = record.data[reading];
                    std.debug.print("PublicKey size is {} bytes\n", .{keysize});
                    reading += 1;
                    // FIXME not sure if parsing this in a right way
                    var coord_size: usize = record.data[reading] * 8;
                    reading += 1;
                    std.debug.print("Public Key X: ", .{});
                    for (record.data[reading .. reading + coord_size]) |byte| {
                        std.debug.print("{X:0>2}", .{byte});
                    }
                    reading += coord_size;
                    std.debug.print("\nPublic Key Y: ", .{});
                    for (record.data[reading .. reading + coord_size]) |byte| {
                        std.debug.print("{X:0>2}", .{byte});
                    }
                    reading += coord_size;
                    std.debug.print("\nHashing algorithm is {}\n", .{@intToEnum(enums.HashAlgorithm, record.data[reading])});
                    std.debug.print("Signature algorithm is {}\n", .{@intToEnum(enums.SignatureAlgorithm, record.data[reading + 1])});
                    reading += 2;
                    const signature_size = @intCast(u16, record.data[reading]) << 8 | record.data[reading + 1];
                    std.debug.print("Signature size is {d} bytes\n", .{signature_size});
                    reading += 2;
                    std.debug.print("Signature is 0x", .{});
                    for (record.data[reading .. reading + signature_size]) |byte| {
                        std.debug.print("{X:0>2}", .{byte});
                    }
                    std.debug.print("\n", .{});
                },
                .server_hello_done => {},
                .certificate_status => {
                    std.debug.print("certificate_status debug info unimplemented\n", .{});
                },
                // TODO: implement certificate status info
                else => return error.unsupported_handshake_type,
            }
        },
        .alert => {
            std.debug.print("Alert type is {}\n", .{@intToEnum(enums.AlertLevel, record.data[0])});
            std.debug.print("Alert description: {}\n", .{@intToEnum(enums.AlertDescription, record.data[1])});
        },
        .change_cipher_spec => {},
        .application_data => {},
        .heartbeat => {},
        else => return error.unsupported_record_type,
    }
}

/// Prints slice as hex code to console with note about slice content
pub fn showMem(slice: []u8, note: []const u8) void {
    std.log.debug("examining memory \"{s}\" ({d} bytes)", .{ note, slice.len });
    var i: usize = 0;
    while (i < slice.len) : (i += 1) {
        if (i % 32 == 0) {
            if (i != 0) std.debug.print("\n", .{});
            std.debug.print("{X:0>16}:", .{@ptrToInt(&slice[i])});
        }
        std.debug.print(" {X:0>2}", .{slice[i]});
    }
    std.debug.print("\n", .{});
}
