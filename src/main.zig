const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;
const Thread = std.Thread;

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
    var memory_buffer: [1024 * 1024 * 4]u8 = undefined;
    var fixed_buffer_allocator = heap.FixedBufferAllocator.init(&memory_buffer);
    while (running) {
        var request_allocator = &fixed_buffer_allocator.allocator;
        defer fixed_buffer_allocator.reset();
        const client_socket = try socket.accept();
        defer client_socket.close();
        const start_timestamp = std.time.nanoTimestamp();

        var buffer: [2056]u8 = undefined;
        var received = client_socket.receive(buffer[0..]) catch |e| {
            debug.print("=== receive error 1 ===\n", .{});
            continue;
        };

        const request = try parsing.Request.fromSlice(request_allocator, buffer[0..received]);
        if (request.request_line.method == .get) {
            const resource_slice = request.request_line.resourceSlice()[1..];
            const resource = if (mem.eql(u8, resource_slice, "")) "index.html" else resource_slice;
            const static_path = try mem.concat(
                request_allocator,
                u8,
                &[_][]const u8{ "static/", resource },
            );

            const file_data = fs.cwd().readFileAlloc(request_allocator, static_path, max_size) catch |e| {
                switch (e) {
                    error.FileNotFound => {
                        _ = client_socket.send("HTTP/1.1 404 NOT FOUND\n\nFile cannot be found\n\n") catch |send_error| {
                            debug.print("=== send error 404 ===\n", .{});
                        };
                        debug.print("==== 404 ({}) ====\n", .{static_path});
                        continue;
                    },
                    error.OutOfMemory => {
                        _ = client_socket.send("HTTP/1.1 500 Internal server error\n\nOut of memory\n\n") catch |send_error| {
                            debug.print("=== send error 500 ===\n", .{});
                        };
                        debug.print("==== 500 Out of memory ({}) ====\n", .{static_path});
                        continue;
                    },

                    error.EndOfStream,
                    error.InputOutput,
                    error.IsDir,
                    error.OperationAborted,
                    error.BrokenPipe,
                    error.ConnectionResetByPeer,
                    error.SystemResources,
                    error.WouldBlock,
                    error.FileTooBig,
                    error.AccessDenied,
                    error.ConnectionTimedOut,
                    error.Unexpected,
                    error.Unseekable,
                    error.SharingViolation,
                    error.PathAlreadyExists,
                    error.PipeBusy,
                    error.NameTooLong,
                    error.InvalidUtf8,
                    error.BadPathName,
                    error.SymLinkLoop,
                    error.ProcessFdQuotaExceeded,
                    error.SystemFdQuotaExceeded,
                    error.NoDevice,
                    error.NoSpaceLeft,
                    error.NotDir,
                    error.DeviceBusy,
                    error.FileLocksNotSupported,
                    => {
                        _ = client_socket.send("HTTP/1.1 500 Internal server error\n\n") catch |send_error| {
                            debug.print("=== send error 500 ===\n", .{});
                        };
                        debug.print("==== 500 ({}) ({}) ====\n", .{ static_path, e });
                        continue;
                    },
                }
            };

            const expected_file_size = file_data.len;
            _ = client_socket.send("HTTP/1.1 200 OK\n") catch unreachable;
            var content_type_buffer: [64]u8 = undefined;
            const content_type_header = try fmt.bufPrint(
                &content_type_buffer,
                "Content-type: {}\n",
                .{determineContentType(static_path)},
            );
            _ = client_socket.send(content_type_header) catch unreachable;
            _ = client_socket.send("\n") catch unreachable;
            var sent = client_socket.send(file_data) catch |send_error| {
                debug.print("=== send error 200 ===\n", .{});
                continue;
            };
            while (sent < expected_file_size) : (sent += try client_socket.send(file_data[sent..])) {}
            _ = client_socket.send("\n\n") catch unreachable;
            const end_timestamp = std.time.nanoTimestamp();
            debug.print("=== 200 ({}), {} ns ===\n", .{ static_path, end_timestamp - start_timestamp });
        }
    }
}

fn determineContentType(path: []const u8) []const u8 {
    return if (mem.endsWith(u8, path, ".zig") or
        mem.endsWith(u8, path, ".txt") or
        mem.endsWith(u8, path, ".h") or
        mem.endsWith(u8, path, ".c") or
        mem.endsWith(u8, path, ".md") or
        mem.endsWith(u8, path, ".cpp") or
        mem.endsWith(u8, path, ".cc") or
        mem.endsWith(u8, path, ".hh"))
        "text/plain"
    else if (mem.endsWith(u8, path, ".html"))
        "text/html"
    else if (mem.endsWith(u8, path, ".json"))
        "application/json"
    else
        "application/octet-stream";
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

const max_size = 3_000_000_000;
