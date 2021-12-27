const std = @import("std");
const bigInt = std.math.big.int.Managed;

const Point = struct {
    x: *bigInt,
    y: *bigInt,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const alloc = &gpa.allocator;

    var gx = try bigInt.init(alloc);
    defer gx.deinit();

    var gy = try bigInt.init(alloc);
    defer gy.deinit();

    var G: Point = .{
        .x = &gx,
        .y = &gy,
    };

    try ECCPointDouble(alloc, G);
    std.debug.print("G: {any}\n", .{G});
}

/// Point doubling
/// lambda = (3X^2 + a)/(2y)
/// xr = lambda^2 - x1 - x2
/// yr = lambda(x1 - x2)-y1
pub fn ECCPointDouble(alloc: *std.mem.Allocator, P: Point) anyerror!void {
    var divident = try bigInt.init(alloc);
    defer divident.deinit();
    var divider = try bigInt.init(alloc);
    defer divider.deinit();
    var lambda = try bigInt.init(alloc);
    defer lambda.deinit();
    var temp = try bigInt.initSet(alloc, 3);
    defer temp.deinit();

    var result_x = try bigInt.init(alloc);
    errdefer result_x.deinit();
    var result_y = try bigInt.init(alloc);
    errdefer result_y.deinit();
    var result: Point = .{
        .x = &result_x,
        .y = &result_y,
    };

    try bigInt.pow(&divident, P.x.toConst, 2);
    try bigInt.mul(&divident, divident.toConst(), temp.toConst());
    // FIXME add proper eliptic curve parameter
    try temp.setString(16,  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    try bigInt.add(&divident, divident.toConst(), temp.toConst());
    try temp.set(2);
    try bigInt.mul(&divider, P.y.toConst(), temp.toConst());
    try bigInt.divFloor(&temp, &lambda, divident.toConst(), divider.toConst());
    try bigInt.pow(result.x, lambda.toConst(), 2);
    try bigInt.sub(result.x, result.x.toConst(), P.x.toConst());
    try bigInt.sub(result.x, result.x.toConst(), P.x.toConst());

    try bigInt.sub(result.y, P.x.toConst(), result.x.toConst());
    try bigInt.mul(result.y, result.y.toConst(), lambda.toConst());
    try bigInt.sub(result.y, result.y.toConst(), P.y.toConst());

    return result;
}

/// Point addition
/// xr = lambda^2 - x1 - x2
/// yr = lambda(x1 - x2)-y1
pub fn ECCPointAdd() void {

}