const std = @import("std");
const tls = @import("tls.zig");
const debug = @import("debug.zig");

const allocator = std.mem.Allocator;
const ws = std.os.windows.ws2_32;
const bigInt = std.math.big.int.Managed;

pub fn main() anyerror!void {
    _ = try std.os.windows.WSAStartup(2, 2);
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    var TLShandle: usize = try tls.initTLS("google.com", &gpa.allocator);
    _ = TLShandle;
    _ = try std.os.windows.WSACleanup();

    // // EXCHANGE KEY GENERATION with secp256r1 curve
    // var p_val: bigInt = try bigInt.init(&gpa.allocator);
    // var a_val: bigInt = try bigInt.init(&gpa.allocator);
    // var b_val: bigInt = try bigInt.init(&gpa.allocator);
    // var gx_val: bigInt = try bigInt.init(&gpa.allocator);
    // var gy_val: bigInt = try bigInt.init(&gpa.allocator);
    // var n_val: bigInt = try bigInt.init(&gpa.allocator);
    // defer p_val.deinit();
    // defer a_val.deinit();
    // defer b_val.deinit();
    // defer gx_val.deinit();
    // defer gy_val.deinit();
    // defer n_val.deinit();
    // try a_val.setString(16,  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    // try p_val.setString(16,  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    // try b_val.setString(16,  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    // try gx_val.setString(16, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    // try gy_val.setString(16, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    // try n_val.setString(16,  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    // const a = a_val.toConst();
    // const p = p_val.toConst();
    // const b = b_val.toConst();
    // const gx = gx_val.toConst();
    // const gy = gy_val.toConst();
    // const n = n_val.toConst();

    // var x3_val: bigInt = try bigInt.init(&gpa.allocator);
    // var ax_val: bigInt = try bigInt.init(&gpa.allocator);
    // var res_val: bigInt = try bigInt.init(&gpa.allocator);
    // defer x3_val.deinit();
    // defer ax_val.deinit();
    // defer res_val.deinit();
    
    // std.log.debug("p:   {d:0>80}", .{p});
    // std.log.debug("a:   {any}", .{a});
    // std.log.debug("b:   {any}", .{b});
    // std.log.debug("gx:  {any}", .{gx});
    // std.log.debug("gy:  {any}", .{gy});
    // std.log.debug("n:   {any}", .{n});

    // //  y^2 = x^3 + ax + b
    // // Point belong to curve if (X^3 + AX + B) % P == 0

    // // x^3 & ax
    // try bigInt.pow(&x3_val, gx, 3);
    // try bigInt.mul(&ax_val, a, gx);

    // // x^3 + ax
    // const ax = ax_val.toConst();
    // const x3 = x3_val.toConst();
    // var temp_val_1: bigInt = try bigInt.init(&gpa.allocator);
    // defer temp_val_1.deinit();
    // try bigInt.add(&temp_val_1, x3, ax);

    // // (x^3 + ax) + b
    // const temp_const_1 = temp_val_1.toConst();
    // var temp_val_2: bigInt = try bigInt.init(&gpa.allocator);
    // defer temp_val_2.deinit();
    // try bigInt.add(&temp_val_2, temp_const_1, b);

    // // (x^3 + ax) + b
    // var temp_val_y: bigInt = try bigInt.init(&gpa.allocator);
    // defer temp_val_y.deinit();
    // try bigInt.pow(&temp_val_y, gy, 2);
    // const temp_const_y = temp_val_y.toConst();
    // const temp_const_2 = temp_val_2.toConst();
    // var temp_val_3: bigInt = try bigInt.init(&gpa.allocator);
    // defer temp_val_3.deinit();
    // try bigInt.sub(&temp_val_3, temp_const_2, temp_const_y);

    // // (x^3 + ax + b) % p
    // const temp_const_3 = temp_val_3.toConst();
    // var ignore: bigInt = try bigInt.init(&gpa.allocator);
    // defer ignore.deinit();
    // try bigInt.divFloor(&ignore, &res_val, temp_const_3, p);

    // std.log.debug("res: {any}", .{res_val});


    // // generate random 32byte (not 32bit) number
    // var randomdata: []u8 = try gpa.allocator.alloc(u8, 32);
    // defer gpa.allocator.free(randomdata);

    // var rng = std.rand.DefaultPrng.init(@intCast(u64, std.time.timestamp()));
    // for (randomdata) |*pointer| pointer.* = rng.random.int(u8);

    // var texto: []u8 = try debug.sliceToHexString(&gpa.allocator, randomdata);
    // defer gpa.allocator.free(texto);

    // var randomtext: bigInt = try bigInt.init(&gpa.allocator);
    // defer randomtext.deinit();
    // try randomtext.setString(16, texto);

    // std.log.debug("{any}", .{randomtext});
}
