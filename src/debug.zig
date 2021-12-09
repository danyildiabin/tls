const std = @import("std");

// Converts hex string to slice with same data as it is in string
pub fn hexStringToSlice(alloc: *std.mem.Allocator, string: []const u8) anyerror![]u8 {
    var filled: usize = 0;
    var data: []u8 = try alloc.alloc(u8, string.len >> 1);
    for (string) |char, index| {
        if (index % 2 == 0) {
            
            data[index >> 1] = switch (char) {
                '0'...'9' => blk: { break :blk char - 48;},
                'A'...'F' => blk: { break :blk char - 55;},
                'a'...'f' => blk: { break :blk char - 87;},
                else => unreachable
            } << 4;
        } else {
            data[index >> 1] |= switch (char) {
                '0'...'9' => blk: { break :blk char - 48;},
                'A'...'F' => blk: { break :blk char - 55;},
                'a'...'f' => blk: { break :blk char - 87;},
                else => unreachable
            };
        }
    }
    return data;
}

// Prints slice as hex code to console with note about slice content
pub fn showMem(slice: []u8, note: []const u8) void {
    std.log.debug("examining memory \"{s}\" ({d} bytes)", .{note, slice.len});
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