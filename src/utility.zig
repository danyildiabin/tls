const std = @import("std");

/// Converts hex string to slice with same data as it is in string
pub fn hexStringToSlice(alloc: *std.mem.Allocator, string: []const u8) anyerror![]u8 {
    var data: []u8 = try alloc.alloc(u8, string.len >> 1);
    errdefer alloc.free(data);
    for (string) |char, index| {
        if (index % 2 == 0) {
            data[index >> 1] = switch (char) {
                '0'...'9' => blk: {
                    break :blk char - 48;
                },
                'A'...'F' => blk: {
                    break :blk char - 55;
                },
                'a'...'f' => blk: {
                    break :blk char - 87;
                },
                else => return error.unsupported_character,
            } << 4;
        } else {
            data[index >> 1] |= switch (char) {
                '0'...'9' => blk: {
                    break :blk char - 48;
                },
                'A'...'F' => blk: {
                    break :blk char - 55;
                },
                'a'...'f' => blk: {
                    break :blk char - 87;
                },
                else => return error.unsupported_character,
            };
        }
    }
    return data;
}

/// Converts hex string to slice with same data as it is in string
pub fn sliceToHexString(alloc: *std.mem.Allocator, slice: []const u8) anyerror![]u8 {
    var data = try alloc.alloc(u8, slice.len * 2);
    errdefer alloc.free(data);
    // FIXME edit loop to remove unused "byte" var
    for (slice) |byte, i| {
        _ = try std.fmt.bufPrint(data[i * 2 .. (i + 1) * 2], "{X:0>2}", .{slice[i]});
        _ = byte;
    }
    return data;
}
