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
                .value = [_]u8{ 0, 0, 0, 0 },
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
        var request_stack_allocator = &fixed_buffer_allocator.allocator;
        defer fixed_buffer_allocator.reset();
        var backup_arena = heap.ArenaAllocator.init(heap.page_allocator);
        defer backup_arena.deinit();
        var backup_allocator = &backup_arena.allocator;
        const client_socket = try socket.accept();
        defer client_socket.close();
        const start_timestamp = std.time.nanoTimestamp();

        var buffer: [2056]u8 = undefined;
        var received = client_socket.receive(buffer[0..]) catch |e| {
            debug.print("=== receive error 1 ===\n", .{});
            continue;
        };

        const request = try parsing.Request.fromSlice(request_stack_allocator, buffer[0..received]);
        if (request.request_line.method == .get) {
            const resource_slice = request.request_line.resourceSlice()[1..];
            const resource = if (mem.eql(u8, resource_slice, "")) "index.html" else resource_slice;
            const static_path = try mem.concat(
                request_stack_allocator,
                u8,
                &[_][]const u8{ "static/", resource },
            );

            debug.print("==> {} {}\n", .{ request.request_line.method.toSlice(), static_path });

            const file_data = fs.cwd().readFileAlloc(
                request_stack_allocator,
                static_path,
                max_stack_file_read_size,
            ) catch |e| err: {
                switch (e) {
                    error.FileNotFound => {
                        _ = client_socket.send(
                            "HTTP/1.1 404 NOT FOUND\n\nFile cannot be found\n\n",
                        ) catch |send_error| {
                            debug.print("=== send error 404 ===\n", .{});
                        };
                        debug.print("<== 404 ({})\n", .{static_path});
                        continue;
                    },
                    error.OutOfMemory => {
                        var file_data = try fs.cwd().readFileAlloc(
                            backup_allocator,
                            static_path,
                            max_heap_file_read_size,
                        );
                        debug.print(
                            "|== File too big for stack, allocating on heap ({})\n",
                            .{static_path},
                        );

                        break :err file_data;
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
                        _ = client_socket.send("HTTP/1.1 500 Internal server error\n\n") catch
                            |send_error| {
                            debug.print("=== send error 500 ===\n", .{});
                        };
                        debug.print("<== 500 ({}) ({})\n", .{ static_path, e });
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
            while (sent < expected_file_size) : ({
                // @TODO: add proper error handling here, like other cases
                sent += try client_socket.send(file_data[sent..]);
            }) {}
            _ = client_socket.send("\n\n") catch unreachable;
            const end_timestamp = std.time.nanoTimestamp();
            const timestamp_in_ms = @intToFloat(f64, end_timestamp - start_timestamp) / 1_000_000.0;
            debug.print("<== 200 ({}), {d:.3} ms\n", .{ static_path, timestamp_in_ms });
        }
    }
}

fn determineContentType(path: []const u8) []const u8 {
    return if (endsWithAny(
        u8,
        path,
        &[_][]const u8{ ".zig", ".txt", ".h", ".c", ".md", ".cpp", ".cc", ".hh" },
    ))
        "text/plain"
    else if (mem.endsWith(u8, path, ".html") or mem.endsWith(u8, path, ".htm"))
        "text/html"
    else if (mem.endsWith(u8, path, ".jpg") or mem.endsWith(u8, path, ".jpeg"))
        "image/jpeg"
    else if (mem.endsWith(u8, path, ".png"))
        "image/png"
    else if (mem.endsWith(u8, path, ".json"))
        "application/json"
    else
        "application/octet-stream";
}

fn endsWithAny(comptime T: type, slice: []const T, comptime suffixes: []const []const T) bool {
    inline for (suffixes) |suffix| {
        if (mem.endsWith(T, slice, suffix)) return true;
    }

    return false;
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

const max_stack_file_read_size = 3_000_000_000;
const max_heap_file_read_size = 1_000_000_000_000;
