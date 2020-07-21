const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;

const network = @import("network");

pub fn main() anyerror!void {
    try network.init();
    defer network.deinit();

    const endpoint = network.EndPoint{
        .address = network.Address{
            .ipv4 = .{
                .value = [_]u8{ 127, 0, 0, 1 },
            },
        },
        .port = 1337,
    };

    const running = true;

    const socket = try network.Socket.create(network.AddressFamily.ipv4, network.Protocol.tcp);
    try socket.bind(endpoint);
    try socket.listen();
    while (running) {
        const client_socket = try socket.accept();
        debug.print("Got client: {}!\n", .{client_socket});
        _ = try client_socket.send("Hello!");
        client_socket.close();
    }

    std.debug.warn("All your codebase are belong to us.\n", .{});
}
