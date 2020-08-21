const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;

const network = @import("network");

const IPv4 = network.Address.IPv4;
const ArrayList = std.ArrayList;

pub const BlockList = struct {
    const Self = @This();

    blocked_addresses: ArrayList(IPv4),

    // @TODO: add support for IPv6 as well
    pub fn fromSlice(allocator: *mem.Allocator, slice: []const u8) !Self {
        var blocked_addresses = ArrayList(IPv4).init(allocator);
        var it = mem.split(slice, "\n");
        while (it.next()) |line| {
            if (mem.eql(u8, line, "")) continue;
            const address = try addressFromSlice(line);
            try blocked_addresses.append(address);
        }

        return Self{ .blocked_addresses = blocked_addresses };
    }

    pub fn isBlocked(self: Self, address: IPv4) bool {
        for (self.blocked_addresses.items) |blocked_address| {
            if (address.eql(blocked_address)) return true;
        }

        return false;
    }
};

fn addressFromSlice(slice: []const u8) !IPv4 {
    var it = mem.split(slice, ".");
    const v1 = try fmt.parseUnsigned(u8, it.next() orelse return error.InvalidAddress, 10);
    const v2 = try fmt.parseUnsigned(u8, it.next() orelse return error.InvalidAddress, 10);
    const v3 = try fmt.parseUnsigned(u8, it.next() orelse return error.InvalidAddress, 10);
    const v4 = try fmt.parseUnsigned(u8, it.next() orelse return error.InvalidAddress, 10);

    return IPv4{ .value = [_]u8{ v1, v2, v3, v4 } };
}
