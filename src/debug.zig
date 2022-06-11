const std = @import("std");
const tls = @import("tls.zig");
const enums = @import("enums.zig");
const structs = @import("structs.zig");

const sliceToInt = std.mem.readIntSliceBig;

pub fn printRecord(record: structs.Record, note: []const u8) anyerror!void {
    std.debug.print("\n===> {s}\n", .{note});
    std.log.debug("Record type is \"{s}\"", .{@tagName(record.type)});
    std.log.debug("Record version is {s}", .{@tagName(record.version)});
    switch (record.type) {
        .handshake => {
            var reading: usize = 0;
            const handshake_type = @intToEnum(enums.HandshakeType, record.data[reading]);
            std.log.debug("Handshake type is {s}", .{@tagName(handshake_type)});
            reading += 1;
            const size = sliceToInt(u24, record.data[reading..reading+3]);
            std.log.debug("Handshake size is {} bytes", .{size});
            reading += 3;
            switch (handshake_type) {
                .client_hello => {
                    const version = sliceToInt(u16, record.data[reading .. reading + 2]);
                    reading += 2;
                    std.log.debug("Protocol version is {s}", .{@tagName(@intToEnum(enums.Version, version))});
                    std.log.debug("Client random is 0x{s}", .{std.fmt.fmtSliceHexUpper(record.data[reading .. reading + 32])});
                    reading += 32;
                    reading += try printSessionID(record.data[reading..record.data.len]);
                    reading += try printCiphersuites(record.data[reading..record.data.len]);
                    reading += try printCompressions(record.data[reading..record.data.len]);
                    reading += try printExtensions(record.data[reading..record.data.len]);
                },
                .server_hello => {
                    const version = sliceToInt(u16, record.data[reading .. reading + 2]);
                    std.log.debug("Protocol version is {s}", .{@tagName(@intToEnum(enums.Version, version))});
                    reading += 2;
                    std.log.debug("Server random is 0x{s}", .{std.fmt.fmtSliceHexUpper(record.data[reading .. reading + 32])});
                    reading += 32;
                    reading += try printSessionID(record.data[reading..record.data.len]);
                    const ciphersuite = sliceToInt(u16, record.data[reading .. reading + 2]);
                    std.log.debug("Selected ciphersuite is {s}", .{@tagName(@intToEnum(enums.CipherSuite, ciphersuite))});
                    reading += 2;
                    // TODO add compressions enum
                    std.log.debug("Selected compression method is 0x{X:0>2}", .{record.data[reading]});
                    reading += 1;
                    reading += try printExtensions(record.data[reading..record.data.len]);
                },
                .certificate => {
                    reading += try printCertificates(record.data[reading..record.data.len]);
                },
                .server_key_exchange => {
                    reading += try printCurveInfo(record.data[reading..record.data.len]);
                    reading += try printPublicKey(record.data[reading..record.data.len]);
                    std.log.debug("Hashing algorithm is {s}", .{@tagName(@intToEnum(enums.HashAlgorithm, record.data[reading]))});
                    reading += 1;
                    std.log.debug("Signature algorithm is {s}", .{@tagName(@intToEnum(enums.SignatureAlgorithm, record.data[reading]))});
                    reading += 1;
                    const signature_size = sliceToInt(u16, record.data[reading .. reading + 2]);
                    reading += 2;
                    std.log.debug("Signature: ({d} bytes) 0x{s}", .{signature_size, std.fmt.fmtSliceHexUpper(record.data[reading .. reading + signature_size])});
                },
                .server_hello_done => {},
                .certificate_status => return error.unimplemented_hadnshake_type,
                // TODO: implement certificate status info
                else => return error.unsupported_handshake_type,
            }
        },
        .alert => {
            std.log.debug("Alert type is {s}\n", .{@tagName(@intToEnum(enums.AlertLevel, record.data[0]))});
            std.log.debug("Alert description: {s}\n", .{@tagName(@intToEnum(enums.AlertDescription, record.data[1]))});
        },
        .change_cipher_spec => return error.unimplemented_record_type,
        .application_data => return error.unimplemented_record_type,
        .heartbeat => return error.unimplemented_record_type,
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

/// returns bytes read
/// Prints extensions section
// TODO: add overflow safety checks
// TODO implement something to show extension info
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
fn printExtensions(remainig_data: []u8) !usize {
    if (remainig_data.len == 0) {
        std.log.debug("Extensions are not provided", .{});
        return 0;
    } else {
        var bytes_read: usize = 0;
        const extensions_size = sliceToInt(u16, remainig_data[bytes_read .. bytes_read + 2]);
        if (remainig_data.len != extensions_size + 2) return error.BadExtensionsLength;
        std.log.debug("Given Extensions: (total size is {d} bytes)", .{extensions_size});
        bytes_read += 2;

        while (true) {
            const extension = @intToEnum(enums.ExtensionType, sliceToInt(u16, remainig_data[bytes_read .. bytes_read + 2]));
            bytes_read += 2;
            const extensionsize = sliceToInt(u16, remainig_data[bytes_read .. bytes_read + 2]);
            bytes_read += 2;
            std.log.debug("{s}, size is {d} bytes: 0x{s}", .{ @tagName(extension), extensionsize, std.fmt.fmtSliceHexUpper(remainig_data[bytes_read .. bytes_read + extensionsize]) });
            bytes_read += extensionsize;
            if (bytes_read >= remainig_data.len) return bytes_read;
        }
    }
}

// TODO: add compressions enum
// TODO: add overflow safety checks
fn printCompressions(remainig_data: []u8) !usize {
    const compression_n = remainig_data[0];
    var bytes_read: usize = 1;
    if (compression_n == 0) {
        std.log.debug("No compression algorithms proposed", .{});
    } else {
        std.log.debug("Proposed {d} compression algorithms:", .{compression_n});
        for (remainig_data[1 .. 1 + compression_n]) |byte| {
            std.log.debug("0x{X:0>2}", .{byte});
        }
        bytes_read += compression_n;
    }
    return bytes_read;
}

// TODO: add overflow safety checks
fn printCiphersuites(remainig_data: []u8) !usize {
    var bytes_read: usize = 0;
    const ciphersuites_n = sliceToInt(u16, remainig_data[bytes_read .. bytes_read + 2]) >> 1;
    std.log.debug("Proposed {d} ciphersuites:", .{ciphersuites_n});
    bytes_read += 2;
    var ciphersuites = std.mem.bytesAsSlice(u16, remainig_data[bytes_read .. bytes_read + (ciphersuites_n << 1)]);
    for (ciphersuites) |ciphersuite| {
        std.log.debug("{s}", .{@tagName(@intToEnum(enums.CipherSuite, std.mem.bigToNative(u16, ciphersuite)))});
    }
    bytes_read += ciphersuites_n << 1;
    return bytes_read;
}

// TODO: add overflow safety checks
fn printSessionID(remainig_data: []u8) !usize {
    var bytes_read: usize = 1;
    if (remainig_data[0] == 0) {
        std.log.debug("Session ID is not provided", .{});
    } else {
        std.log.debug("Session ID is 0x{s}", .{std.fmt.fmtSliceHexUpper(remainig_data[bytes_read .. bytes_read + remainig_data[0]])});
        bytes_read += remainig_data[0];
    }
    return bytes_read;
}

// TODO: add overflow safety checks
fn printCertificates(remainig_data: []u8) !usize {
    var bytes_read: usize = 0;
    const combined_size: u64 = sliceToInt(u24, remainig_data[bytes_read .. bytes_read + 3]);
    std.log.debug("All certificates with size headers is {d} bytes", .{combined_size});
    bytes_read += 3;
    var certificate_n: usize = 0;
    while (true) {
        certificate_n += 1;
        const cert_size: u64 = sliceToInt(u24, remainig_data[bytes_read .. bytes_read + 3]);
        std.log.debug("Certificate #{d} is {d} bytes long", .{ certificate_n, cert_size });
        bytes_read += 3 + cert_size;
        if (bytes_read > remainig_data.len) return error.OutOfBounds;
        if (bytes_read == remainig_data.len) break;
    }
    return bytes_read;
}

//=======================================================
// https://www.rfc-editor.org/rfc/rfc4492#section-5.4
//=======================================================
// struct {
//     ECCurveType    curve_type;
//     select (curve_type) {
//         case explicit_prime:
//             opaque      prime_p <1..2^8-1>;
//             ECCurve     curve;
//             ECPoint     base;
//             opaque      order <1..2^8-1>;
//             opaque      cofactor <1..2^8-1>;
//         case explicit_char2:
//             uint16      m;
//             ECBasisType basis;
//             select (basis) {
//                 case ec_trinomial:
//                         opaque  k <1..2^8-1>;
//                 case ec_pentanomial:
//                         opaque  k1 <1..2^8-1>;
//                         opaque  k2 <1..2^8-1>;
//                         opaque  k3 <1..2^8-1>;
//             };
//             ECCurve     curve;
//             ECPoint     base;
//             opaque      order <1..2^8-1>;
//             opaque      cofactor <1..2^8-1>;
//         case named_curve:
//             NamedCurve namedcurve;
//     };
// } ECParameters;
//=======================================================
// TODO: implement explicit_prime and explicit_char2 parsing
fn printCurveInfo(remainig_data: []u8) !usize {
    var bytes_read: usize = 0;
    const curve_type = @intToEnum(enums.ECCurveType, remainig_data[bytes_read]);
    std.log.debug("Curve type is {s}", .{@tagName(curve_type)});
    bytes_read += 1;
    switch (curve_type) {
        .explicit_prime => return error.explicit_prime_curve_unimplemented,
        .explicit_char2 => return error.explicit_char2_curve_unimplemented,
        .named_curve => {
            const curve = @intToEnum(enums.EllipticCurve, sliceToInt(u16, remainig_data[bytes_read .. bytes_read + 2]));
            std.log.debug("Selected named curve is {s}", .{@tagName(curve)});
            bytes_read += 2;
        },
        else => return error.unsupported_curve_type,
    }
    return bytes_read;
}

// TODO: should look at supportedd formats extension provided by server_hello
// ! https://www.rfc-editor.org/rfc/rfc5480#section-2.2
// https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
fn printPublicKey(remainig_data: []u8) !usize {
    var bytes_read: usize = 0;
    const keysize = remainig_data[bytes_read];
    std.log.debug("Public Key: ({d} bytes)", .{keysize});
    bytes_read += 1;
    std.log.debug("Assuming uncopmressed key format selected in server_hello", .{});
    if (remainig_data[bytes_read] != 4) return error.unsupported_key_format; 
    bytes_read += 1;
    const coordsize = (keysize-1)>>1;
    std.log.debug("X of public key point: 0x{s}", .{std.fmt.fmtSliceHexUpper(remainig_data[bytes_read .. bytes_read + coordsize])});
    bytes_read += coordsize;
    std.log.debug("Y of public key point: 0x{s}", .{std.fmt.fmtSliceHexUpper(remainig_data[bytes_read .. bytes_read + coordsize])});
    bytes_read += coordsize;
    return bytes_read;
}