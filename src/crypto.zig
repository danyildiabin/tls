const std = @import("std");
const Managed = std.math.big.int.Managed;
const Const = std.math.big.int.Const;
const enums = @import("enums.zig");
const structs = @import("structs.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    // defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var curve = try structs.Curve.init(allocator, structs.Curve.testCurve);
    defer curve.free();

    var x = try Managed.init(allocator);
    defer x.deinit();
    var y = try Managed.init(allocator);
    defer y.deinit();

    try x.setString(16, "c");
    try y.setString(16, "1");
    var g1 = structs.Point{
        .x = x,
        .y = y,
    };

    var point_res = try ECCPointAdd(allocator, &curve.g, &g1, curve);
    std.debug.print("G: {any}\n", .{point_res});
}

/// ECC Point addition for y^2 = x^3 + ax + b
pub fn ECCPointAdd(allocator: std.mem.Allocator, p1: *structs.Point, p2: *structs.Point, curve: structs.Curve) anyerror!structs.Point {
    // result declarations
    var result_x: Managed = try Managed.init(allocator);
    errdefer result_x.deinit();
    var result_y = try Managed.init(allocator);
    errdefer result_y.deinit();
    var result: structs.Point = .{
        .x = result_x,
        .y = result_y,
    };

    // TODO: check if two points are on curve
    // TODO: check for point at infinity
    if (Managed.eq(p1.x, p2.x) == true) {
        if (Managed.eq(p1.y, p2.y) == true) {
        // TODO: point doubling occurs here because we're adding point to itself
        // P(x1, y1) + P(x1, y1) = P(x3, y3)
        // lambda = (3*x1^2+a)/(2*y1)
        // x3 = lambda^2-x1-x2
        // y3 = lambda*(x1-x3)-y1

        // temp variables to avoid aliases with bigint operations
        var answer = try Managed.init(allocator);
        defer answer.deinit();
        var temp = try Managed.init(allocator);
        defer temp.deinit();
        var temp3 = try Managed.init(allocator);
        defer temp3.deinit();
        var lambda = try Managed.init(allocator);
        defer lambda.deinit();

        std.debug.print("Info: Calculating point doubling \n", .{});
        std.debug.print("Info: Curve mod p = {any}\n", .{curve.p});
        std.debug.print("Info: Curve A = {any}\n", .{curve.a});
        std.debug.print("Info: Point = ({any}, {any})\n", .{ p1.x, p1.y });

        // lambda = x1^2
        try Managed.pow(&lambda, p1.x.toConst(), 2);
        std.debug.print("Assertion: (x1^2) = {any}\n", .{lambda});

        // lambda = 3*(x1^2)
        try temp.copy(lambda.toConst());
        try temp3.set(3);
        try Managed.ensureMulCapacity(&lambda, temp.toConst(), temp3.toConst());
        try Managed.mul(&lambda, temp.toConst(), temp3.toConst());
        std.debug.print("Assertion: 3*(x1^2) = {any}\n", .{lambda});

        // lambda = 3*(x1^2)+a
        try temp.copy(lambda.toConst());
        try Managed.add(&lambda, temp.toConst(), curve.a.toConst());
        std.debug.print("Assertion: 3*(x1^2)+a = {any}\n", .{lambda});

        // temp = y1*2
        try Managed.add(&temp, p1.y.toConst(), p1.y.toConst());
        std.debug.print("Assertion: 2*y1 = {any}\n", .{temp});

        std.debug.print("Operands before sign control: {any}/{any}\n", .{ lambda, temp });
        // This block makes sure divisor is always positive so multiplicative inverse could be used on it
        // NOTE: I managed to implement multiplicative inverse for positive integers only
        if (temp.isPositive() and lambda.isPositive()) {
            // divident and divisor are positive so we don't need to change anything
        } else if (!temp.isPositive() and !lambda.isPositive()) {
            // divident and divisor are negative so they cancel
            // each other and we can ignore minuses in this case
            lambda.setSign(true);
            temp.setSign(true);
        } else if (lambda.isPositive()) {
            // either divident or divisor is negative so result will be negative
            // knowing that result will be negative we can make divident negative
            // and divisor positive to allow multiplicative inverse operation on it
            lambda.setSign(false);
            temp.setSign(true);
        }
        std.debug.print("Operands after sign controll: {any}/{any}\n", .{ lambda, temp });

        // temp2 = temp^(-1)
        std.debug.print("Operands before multiplicative inversion: {any} (mod {any})\n", .{ temp, curve.p });
        var temp2 = try modInverse(allocator, temp, curve.p);
        std.debug.print("Assertion: {any} * {any} = 1 (mod {any})\n", .{ temp, temp2, curve.p });

        // lambda = (y2-y1) * (x2-x1)^(-1)
        try temp.copy(lambda.toConst());
        try Managed.ensureMulCapacity(&lambda, temp.toConst(), temp2.toConst());
        try Managed.mul(&lambda, temp.toConst(), temp2.toConst());
        std.debug.print("Assertion: lambda is {any}\n", .{lambda});

        // lambda^2
        try Managed.pow(&answer, lambda.toConst(), 2);
        std.debug.print("Assertion: lambda^2 = {any}\n", .{answer});
        // - x1
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, temp.toConst(), p1.x.toConst());
        std.debug.print("Assertion: lambda^2 - x1 = {any}\n", .{answer});
        // - x2
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, temp.toConst(), p2.x.toConst());
        std.debug.print("Assertion: lambda^2 - x1 - x2 = {any}\n", .{answer});
        // mod p
        try adaptToField(allocator, &answer, curve.p.toConst());
        try result.x.copy(answer.toConst());

        // y3 = lambda*(x1-x3)-y1
        // x1 - x3
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, p1.x.toConst(), temp.toConst());
        // * lambda
        try temp.copy(answer.toConst());
        try Managed.ensureMulCapacity(&answer, temp.toConst(), lambda.toConst());
        try Managed.mul(&answer, temp.toConst(), lambda.toConst());
        // - y1
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, temp.toConst(), p1.y.toConst());
        // mod p
        try adaptToField(allocator, &answer, curve.p.toConst());
        try result.y.copy(answer.toConst());

        return result;
        } else {
            // TODO: return point at infinity because points result in straight vertical line
            return error.unimplemented_case;
        }
    } else {
        // P(x1, y1) + P(x2, y2) = P(x3, y3)
        // lambda = (y2-y1)/(x2-x1)
        // x3 = lambda^2-x1-x2
        // y3 = lambda*(x1-x3)-y1

        // temp variables to avoid aliases
        var answer = try Managed.init(allocator);
        defer answer.deinit();
        var temp = try Managed.init(allocator);
        defer temp.deinit();
        var lambda = try Managed.init(allocator);
        defer lambda.deinit();

        std.debug.print("Info: Curve mod p = {any}\n", .{curve.p});
        std.debug.print("Info: Curve A = {any}\n", .{curve.a});
        std.debug.print("Info: Curve B = {any}\n", .{curve.b});
        std.debug.print("Info: Point 1 = ({any}, {any})\n", .{ p1.x, p1.y });
        std.debug.print("Info: Point 2 = ({any}, {any})\n", .{ p2.x, p2.y });

        // lambda = (y2-y1)
        try Managed.sub(&lambda, p2.y.toConst(), p1.y.toConst());
        std.debug.print("Assertion: (y2-y1) = {any}\n", .{lambda});

        // temp = (x2-x1)
        try Managed.sub(&temp, p2.x.toConst(), p1.x.toConst());
        std.debug.print("Assertion: (x2-x1) = {any}\n", .{temp});

        std.debug.print("Operands before sign controll: {any}/{any}\n", .{ lambda, temp });
        // This block makes sure divisor is always positive so multiplicative inverse could be used on it
        // NOTE: I managed to implement multiplicative inverse for positive integers only
        if (temp.isPositive() and lambda.isPositive()) {
            // divident and divisor are positive so we don't need to change anything
        } else if (!temp.isPositive() and !lambda.isPositive()) {
            // divident and divisor are negative so they cancel
            // each other and we can ignore minuses in this case
            lambda.setSign(true);
            temp.setSign(true);
        } else if (lambda.isPositive()) {
            // either divident or divisor is negative so result will be negative
            // knowing that result will be negative we can make divident negative
            // and divisor positive to allow multiplicative inverse operation on it
            lambda.setSign(false);
            temp.setSign(true);
        }
        std.debug.print("Operands after sign controll: {any}/{any}\n", .{ lambda, temp });

        // temp2 = temp^(-1)
        std.debug.print("Operands before multiplicative inversion: {any} (mod {any})\n", .{ temp, curve.p });
        var temp2 = try modInverse(allocator, temp, curve.p);
        std.debug.print("Assertion: {any} * {any} = 1 (mod {any})\n", .{ temp, temp2, curve.p });

        // lambda = (y2-y1) * (x2-x1)^(-1)
        try temp.copy(lambda.toConst());
        try Managed.ensureMulCapacity(&lambda, temp.toConst(), temp2.toConst());
        try Managed.mul(&lambda, temp.toConst(), temp2.toConst());
        std.debug.print("Assertion: lambda is {any}\n", .{lambda});

        // lambda^2
        try Managed.pow(&answer, lambda.toConst(), 2);
        std.debug.print("Assertion: lambda^2 = {any}\n", .{answer});
        // - x1
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, temp.toConst(), p1.x.toConst());
        std.debug.print("Assertion: lambda^2 - x1 = {any}\n", .{answer});
        // - x2
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, temp.toConst(), p2.x.toConst());
        std.debug.print("Assertion: lambda^2 - x1 - x2 = {any}\n", .{answer});
        // mod p
        try adaptToField(allocator, &answer, curve.p.toConst());
        std.debug.print("X of result point: {any}\n", .{answer});
        try result.x.copy(answer.toConst());

        // y3 = lambda*(x1-x3)-y1
        // x1 - x3
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, p1.x.toConst(), temp.toConst());
        // * lambda
        try temp.copy(answer.toConst());
        try Managed.ensureMulCapacity(&answer, temp.toConst(), lambda.toConst());
        try Managed.mul(&answer, temp.toConst(), lambda.toConst());
        // - y1
        try temp.copy(answer.toConst());
        try Managed.sub(&answer, temp.toConst(), p1.y.toConst());
        // mod p
        try adaptToField(allocator, &answer, curve.p.toConst());
        std.debug.print("Y of result point: {any}\n", .{answer});
        try result.y.copy(answer.toConst());

        return result;
    }
    _ = result;
}

/// x % y
/// Creates Managed bigInt with must be freed manualy
fn mod(allocator: std.mem.Allocator, x: Const, y: Const) !Managed {
    var result = try Managed.init(allocator);
    errdefer result.deinit();

    var temp = try Managed.init(allocator);
    defer temp.deinit();

    try Managed.divTrunc(&temp, &result, x, y);
    return result;
}

/// Extended Euclidean Algorithm
/// use with arena allocator
fn gcdExtended(allocator: std.mem.Allocator, a: Managed, b: Managed, x: *Managed, y: *Managed) anyerror!Managed {
    // base case
    if (a.eqZero()) {
        try x.set(0);
        try y.set(1);
        return b;
    }

    // to store results of resurcive call
    var x1 = try Managed.init(allocator);
    var y1 = try Managed.init(allocator);

    var temp = try Managed.init(allocator);
    var answer = try Managed.init(allocator);

    var temp2 = try mod(allocator, b.toConst(), a.toConst());
    var gcd = try gcdExtended(allocator, temp2, a, &x1, &y1);

    // Update x and y using results of recursive call
    try Managed.divTrunc(&answer, &temp, b.toConst(), a.toConst());
    try temp.copy(answer.toConst());
    try Managed.ensureMulCapacity(&answer, temp.toConst(), x1.toConst());
    try Managed.mul(&answer, temp.toConst(), x1.toConst());
    try temp.copy(answer.toConst());
    try Managed.sub(&answer, y1.toConst(), temp.toConst());
    try x.copy(answer.toConst());
    try y.copy(x1.toConst());
    return gcd;
}

/// finds Multiplicative inverse
/// use with arena allocator
fn modInverse(allocator: std.mem.Allocator, a: Managed, p: Managed) anyerror!Managed {
    
    var x = try Managed.init(allocator);
    defer x.deinit();
    var y = try Managed.init(allocator);
    defer y.deinit();
    var temp = try Managed.init(allocator);
    defer temp.deinit();
    var temp2 = try Managed.init(allocator);
    defer temp2.deinit();
    var result = try Managed.init(allocator);
    errdefer result.deinit();

    var g = try gcdExtended(allocator, a, p, &x, &y);
    defer g.deinit();

    var one = try Managed.initSet(allocator, 1);
    defer one.deinit();
    if (g.eq(one) == false) return error.numbers_are_not_coprime;

    // return res = (x % m + m) % m;
    try Managed.divTrunc(&temp, &result, x.toConst(), p.toConst());
    try temp.copy(result.toConst());
    try Managed.add(&result, temp.toConst(), p.toConst());
    try temp.copy(result.toConst());
    try Managed.divTrunc(&temp2, &result, temp.toConst(), p.toConst());
    return result;
}

/// checks if number number exists in finite field and modifies it if it's not
/// module is only positive
fn adaptToField(allocator: std.mem.Allocator, number: *Managed, module: Const) anyerror!void {
    var result = try Managed.init(allocator);
    defer result.deinit();
    var temp = try Managed.init(allocator);
    defer temp.deinit();
    if (number.isPositive()) {
        // check if number fits in finite field
        const res_bool = try biggerThen(allocator, number.toConst(), module);
        // if it's bigger shorten it with one or more cycles
        if (res_bool) {
            try Managed.divTrunc(&result, &temp, number.toConst(), module);
            try temp.copy(result.toConst());
            try Managed.ensureMulCapacity(&result, temp.toConst(), module);
            try Managed.mul(&result, temp.toConst(), module);
            try Managed.sub(number, number.toConst(), result.toConst());
        }
    } else {
        // make sure number is not few times bigger
        try Managed.divTrunc(&result, &temp, number.toConst(), module);
        result.setSign(true);
        try temp.copy(result.toConst());
        try Managed.ensureMulCapacity(&result, temp.toConst(), module);
        try Managed.mul(&result, temp.toConst(), module);
        try Managed.add(number, number.toConst(), result.toConst());
        // now negative number can be converted to positive with finite field module
        try Managed.add(number, module, number.toConst());
    }
}

/// checks if a is bigger than b
/// when a == b returns false
/// temp may be used for calculations and could be modified
fn biggerThen(allocator: std.mem.Allocator, a: Const, b: Const) anyerror!bool {
    if (a.positive and !b.positive) return true;
    if (!a.positive and b.positive) return false;
    var temp = try Managed.init(allocator);
    defer temp.deinit();
    if (a.positive and b.positive) {
        try Managed.sub(&temp, a, b);
        if (temp.eqZero()) return false;
        if (temp.isPositive()) return true;
        return false;
    } else {
        var a_temp = a.negate();
        var b_temp = b.negate();
        try Managed.sub(&temp, a_temp, b_temp);
        if (temp.eqZero()) return false;
        if (temp.isPositive()) return false;
        return true;
    }
}

// TODO add crypto ecc arithmetic tests
// test "expect addOne adds one to 41" {
//     std.testing.allocator
//     // The Standard Library contains useful functions to help create tests.
//     // `expect` is a function that verifies its argument is true.
//     // It will return an error if its argument is false to indicate a failure.
//     // `try` is used to return an error to the test runner to notify it that the test failed.
//     try std.testing.expect(addOne(41) == 42);
// }
