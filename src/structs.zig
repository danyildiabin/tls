const enums = @import("enums.zig");

pub const handshakeHeader = struct {
    type: enums.HandshakeType,
    data: []u8,
};

pub const ClientHelloRecord = struct {
    version: enums.Version,
    client_random: []u8,
    session_id: ?[]u8,
    cipher_suites: []u16,
    compression_methods: ?[]u8,
    extensions: ?[]Extension,
};

pub const Record = struct {
    type: enums.ContentType,
    version: enums.Version,
    data: []u8,
};

pub const Client = struct {
    cipher: u16,
    session_id: enums.Version,
    compression: []u8,
};

pub const Extension = struct {
    type: enums.ExtensionType,
    data: []u8,
};

pub const ECCPublicKey = struct {
    compressed_y: enums.CompressedY,
    point_x: []u8,
};
