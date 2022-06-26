const bigInt = std.math.big.int.Managed;
const std = @import("std");

const Point = struct {
    x: bigInt,
    y: bigInt,
};

pub const NamedCurve = struct {
    const This = @This();
    alloc: std.mem.Allocator,
    name: EllipticCurve,
    p: bigInt,
    a: bigInt,
    b: bigInt,
    n: bigInt,
    g: Point,

    pub fn init(allocator: std.mem.Allocator, name: EllipticCurve) !This {
        var return_val: This = undefined;
        return_val.alloc = allocator;
        return_val.name = name;
        return_val.p = try bigInt.init(return_val.alloc);
        errdefer return_val.p.deinit();
        return_val.a = try bigInt.init(return_val.alloc);
        errdefer return_val.a.deinit();
        return_val.b = try bigInt.init(return_val.alloc);
        errdefer return_val.b.deinit();
        return_val.n = try bigInt.init(return_val.alloc);
        errdefer return_val.n.deinit();
        return_val.g.x = try bigInt.init(return_val.alloc);
        errdefer return_val.g.x.deinit();
        return_val.g.y = try bigInt.init(return_val.alloc);
        errdefer return_val.g.y.deinit();
        switch (return_val.name) {
            .secp256r1 => {
                try return_val.p.setString(16, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
                try return_val.a.setString(16, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
                try return_val.b.setString(16, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
                try return_val.n.setString(16, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
                try return_val.g.x.setString(16, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
                try return_val.g.y.setString(16, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
            },
            .test_curve => {
                try return_val.p.setString(10, "17");
                try return_val.a.setString(10, "0");
                try return_val.b.setString(10, "7");
                try return_val.n.setString(10, "");
                try return_val.g.x.setString(10, "15");
                try return_val.g.y.setString(10, "13");
            },
            else => return error.unknown_or_unimplemented_curve,
        }
        return return_val;
    }

    pub fn deinit(this: *This) void {
        this.p.deinit();
        this.a.deinit();
        this.b.deinit();
        this.n.deinit();
        this.g.x.deinit();
        this.g.y.deinit();
    }
};

/// Named eliptic curves codes
/// aka TLS Supported Groups
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
pub const EllipticCurve = enum(u16) {
    test_curve = 0, // deprecated
    sect163k1 = 1, // deprecated
    sect163r1 = 2, // deprecated
    sect163r2 = 3, // deprecated
    sect193r1 = 4, // deprecated
    sect193r2 = 5, // deprecated
    sect233k1 = 6, // deprecated
    sect233r1 = 7, // deprecated
    sect239k1 = 8, // deprecated
    sect283k1 = 9, // deprecated
    sect283r1 = 10, // deprecated
    sect409k1 = 11, // deprecated
    sect409r1 = 12, // deprecated
    sect571k1 = 13, // deprecated
    sect571r1 = 14, // deprecated
    secp160k1 = 15, // deprecated
    secp160r1 = 16, // deprecated
    secp160r2 = 17, // deprecated
    secp192k1 = 18, // deprecated
    secp192r1 = 19, // deprecated
    secp224k1 = 20, // deprecated
    secp224r1 = 21, // deprecated
    secp256k1 = 22, // deprecated
    secp256r1 = 23, // recomended
    secp384r1 = 24, // recomended
    secp521r1 = 25, // deprecated
    brainpoolP256r1 = 26, // deprecated
    brainpoolP384r1 = 27, // deprecated
    brainpoolP512r1 = 28, // deprecated
    x25519 = 29, // recomended
    x448 = 30, // recomended
    brainpoolP256r1tls13 = 31,
    brainpoolP384r1tls13 = 32,
    brainpoolP512r1tls13 = 33,
    GC256A = 34,
    GC256B = 35,
    GC256C = 36,
    GC256D = 37,
    GC512A = 38,
    GC512B = 39,
    GC512C = 40,
    curveSM2 = 41,
    ffdhe2048 = 256,
    ffdhe3072 = 257,
    ffdhe4096 = 258,
    ffdhe6144 = 259,
    ffdhe8192 = 260,
    _,
};

/// Point doubling
/// lambda = (3 * (X^2) + a)/(2y)
/// rx = (lambda^2) - x1 - x2
/// ry = lambda * (x1 - rx) - y1
pub fn pointDouble(alloc: std.mem.Allocator, curve: NamedCurve, P: Point) !Point {
    var result: Point = undefined;
    result.x = try bigInt.init(alloc);
    errdefer result.x.deinit();
    result.y = try bigInt.init(alloc);
    errdefer result.y.deinit();

    var divident = try bigInt.init(alloc);
    defer divident.deinit();
    var divisor = try bigInt.init(alloc);
    defer divisor.deinit();
    var lambda = try bigInt.init(alloc);
    defer lambda.deinit();
    var temp = try bigInt.initSet(alloc, 3);
    defer temp.deinit();

    try bigInt.pow(&divident, P.x.toConst(), 2);

    try bigInt.ensureMulCapacity(&divident, divident.toConst(), temp.toConst());
    try bigInt.mul(&divident, divident.toConst(), temp.toConst());

    try bigInt.ensureAddCapacity(&divident, divident.toConst(), curve.a.toConst());
    try bigInt.add(&divident, divident.toConst(), curve.a.toConst());

    try temp.set(2);
    try bigInt.ensureMulCapacity(&divisor, P.y.toConst(), temp.toConst());
    try bigInt.mul(&divisor, P.y.toConst(), temp.toConst());

    try bigInt.divTrunc(&temp, &lambda, divident.toConst(), divisor.toConst());
    std.log.warn("lambda is {d}", .{lambda});
    // lambda is calculated
    try lambda.set(7);

    try bigInt.pow(&result.x, lambda.toConst(), 2);
    std.log.warn("lambda^2 is {d}", .{result.x});
    try bigInt.sub(&result.x, result.x.toConst(), P.x.toConst());
    try bigInt.sub(&result.x, result.x.toConst(), P.x.toConst());
    std.log.warn("lambda^2 - 2x is {d}", .{result.x});

    try bigInt.divTrunc(&temp, &result.x, result.x.toConst(), curve.p.toConst());
    std.log.warn("(lambda^2 - 2x) mod p is {d}", .{result.x});

    try bigInt.sub(&result.y, P.x.toConst(), result.x.toConst());
    std.log.warn("x-xr is {d}", .{result.y});
    try bigInt.ensureMulCapacity(&result.y, result.y.toConst(), lambda.toConst());
    try bigInt.mul(&result.y, result.y.toConst(), lambda.toConst());
    std.log.warn("lambda*(x-xr) is {d}", .{result.y});
    try bigInt.sub(&result.y, result.y.toConst(), P.y.toConst());
    std.log.warn("lambda*(x-xr)-y is {d}", .{result.y});
    try bigInt.divTrunc(&temp, &result.y, result.y.toConst(), curve.p.toConst());
    std.log.warn("lambda*(x-xr)-y mod p is {d}", .{result.y});
    return result;
}

// / Point addition
// / lambda = (3 * (X^2) + a)/(2y)
// / rx = (lambda^2) - x1 - x2
// / ry = lambda * (x1 - rx) - y1
// pub fn pointAdd(alloc: std.mem.Allocator, curve: NamedCurve, P1: Point) !Point {
//     return pointAdd(alloc, curve, P1, P1);
// }
