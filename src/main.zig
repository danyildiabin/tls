const std = @import("std");
const tls = @import("tls.zig");

pub fn main() anyerror!void {
    _ = try std.os.windows.WSAStartup(2, 2);
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    var TLShandle: usize = try tls.initTLS("google.com", &gpa.allocator());
    _ = TLShandle;
    _ = try std.os.windows.WSACleanup();
}
