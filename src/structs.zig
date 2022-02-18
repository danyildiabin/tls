const enums = @import("enums.zig");
const std = @import("std");

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

const Managed = std.math.big.int.Managed;

pub const Point = struct {
    x: std.math.big.int.Managed,
    y: std.math.big.int.Managed,
};

pub const Curve = struct {
    a: Managed,
    b: Managed,
    p: Managed,
    n: Managed,
    g: Point,

    pub fn init(allocator: std.mem.Allocator, comptime name: type) anyerror!Curve {
        // TODO make use of constants
        var a = try Managed.init(allocator);
        var b = try Managed.init(allocator);
        var p = try Managed.init(allocator);
        var n = try Managed.init(allocator);
        var gx = try Managed.init(allocator);
        var gy = try Managed.init(allocator);
        try a.setString(16, name.a);
        try b.setString(16, name.b);
        try p.setString(16, name.p);
        try n.setString(16, name.n);
        try gx.setString(16, name.gx);
        try gy.setString(16, name.gy);
        return Curve{
            .a = a,
            .b = b,
            .p = p,
            .n = n,
            .g = .{
                .x = gx,
                .y = gy,
            },
        };
    }

    pub fn free(self: *Curve) void {
        self.a.deinit();
        self.b.deinit();
        self.p.deinit();
        self.n.deinit();
        self.g.x.deinit();
        self.g.y.deinit();
    }

    pub const testCurve = struct {
        const p = "11";
        const a = "0";
        const b = "7";
        const gx = "2";
        const gy = "a";
        const n = "12";
    };
    pub const secp256r = struct {
        const p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        const a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
        const b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        const gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        const gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        const n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    };
    pub const secp256k = struct {
        const p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        const a = "0000000000000000000000000000000000000000000000000000000000000000";
        const b = "0000000000000000000000000000000000000000000000000000000000000007";
        const gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        const gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        const n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    };
    pub const secp384r1 = struct {
        const p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
        const a = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc";
        const b = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef";
        const gx = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
        const gy = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
        const n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    };
};
