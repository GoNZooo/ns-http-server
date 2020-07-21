const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;

const network = @import("network");

const parsing = @import("./parsing.zig");

pub fn main() anyerror!void {
    try network.init();
    defer network.deinit();

    const endpoint = network.EndPoint{
        .address = network.Address{
            .ipv4 = .{
                .value = [_]u8{ 127, 0, 0, 1 },
            },
        },
        .port = 80,
    };

    const running = true;

    const socket = try network.Socket.create(network.AddressFamily.ipv4, network.Protocol.tcp);
    try socket.bind(endpoint);
    try socket.listen();
    while (running) {
        const client_socket = try socket.accept();
        // debug.print("Got client: {}!\n", .{client_socket});
        var buffer: [2056]u8 = undefined;
        const received = try client_socket.receive(buffer[0..]);
        const request = try parsing.Request.fromSlice(heap.page_allocator, buffer[0..received]);
        debug.print(
            "{}\t{}\n",
            .{ request.request_line.method, request.request_line.resource[0..request.request_line.resource_length] },
        );
        for (request.headers.items) |header| {
            debug.print("\t{}\n", .{header});
        }
        _ = try client_socket.send(html_page);
        client_socket.close();
    }
}

const html_page =
    \\ HTTP/1.1 200 OK
    \\
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <meta charset="UTF-8">
    \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    \\    <title>Document</title>
    \\</head>
    \\<body>
    \\    Hello there!
    \\</body>
    \\</html>
;
