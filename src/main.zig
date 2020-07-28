const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;
const log = std.log;
const process = std.process;
const debug = std.debug;
const Thread = std.Thread;

const network = @import("network");

const parsing = @import("./parsing.zig");

pub const log_level = .info;

const Options = struct {
    const Self = @This();

    maximum_request_memory: ?usize = null,

    pub fn fromArguments(arguments: []const []const u8) !Self {
        var options = Self{};

        var i: usize = 0;
        while (i < arguments.len) : (i += 1) {
            const argument = arguments[i];
            if (mem.eql(u8, argument, "--max-memory")) {
                const maximum_memory = try fmt.parseInt(usize, arguments[i + 1], 10);
                options.maximum_request_memory = maximum_memory;
                i += 1;
            }
        }

        return options;
    }
};

pub fn main() anyerror!void {
    const arguments = try process.argsAlloc(heap.page_allocator);
    defer heap.page_allocator.free(arguments);
    const options = try Options.fromArguments(arguments);
    const maximum_request_heap_size = if (options.maximum_request_memory) |size|
        size
    else
        max_heap_file_read_size;

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
    var memory_buffer: [max_stack_file_read_size]u8 = undefined;
    var fixed_buffer_allocator = heap.FixedBufferAllocator.init(&memory_buffer);
    while (running) {
        var request_stack_allocator = &fixed_buffer_allocator.allocator;
        defer fixed_buffer_allocator.reset();
        const client_socket = try socket.accept();
        defer client_socket.close();
        const start_timestamp = std.time.nanoTimestamp();

        var buffer: [2056]u8 = undefined;
        var received = client_socket.receive(buffer[0..]) catch |e| {
            log.err(.receive, "=== receive error 1 ===\n", .{});
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

            log.info(.request, "==> {} {}\n", .{ request.request_line.method.toSlice(), static_path });

            const file_descriptor = fs.cwd().openFile(static_path, .{}) catch |e| {
                switch (e) {
                    error.FileNotFound => {
                        _ = client_socket.send(
                            "HTTP/1.1 404 NOT FOUND\n\nFile cannot be found\n\n",
                        ) catch |send_error| {
                            log.err(.send, "=== send error 404 ===\n", .{});
                        };
                        log.err(.file, "<== 404 ({})\n", .{static_path});
                        continue;
                    },

                    error.IsDir,
                    error.SystemResources,
                    error.WouldBlock,
                    error.FileTooBig,
                    error.AccessDenied,
                    error.Unexpected,
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
                            log.err(.send, "=== send error 500 ===\n", .{});
                        };
                        log.err(.unexpected, "<== 500 ({}) ({})\n", .{ static_path, e });
                        continue;
                    },
                }
            };

            const expected_file_size = try file_descriptor.getEndPos();
            _ = client_socket.send("HTTP/1.1 200 OK\n") catch unreachable;
            var content_type_buffer: [64]u8 = undefined;
            const content_type_header = try fmt.bufPrint(
                &content_type_buffer,
                "Content-type: {}\n",
                .{determineContentType(static_path)},
            );
            _ = client_socket.send(content_type_header) catch unreachable;
            _ = client_socket.send("\n") catch unreachable;

            var file_buffer = try request_stack_allocator.alloc(u8, max_stack_file_read_size - 500_000);
            var read_bytes = try file_descriptor.read(file_buffer);
            while (read_bytes == file_buffer.len) : (read_bytes = try file_descriptor.read(file_buffer)) {
                _ = try client_socket.send(file_buffer);
            }
            _ = try client_socket.send(file_buffer[0..read_bytes]);

            _ = client_socket.send("\n\n") catch unreachable;
            const end_timestamp = std.time.nanoTimestamp();
            const timestamp_in_ms = @intToFloat(f64, end_timestamp - start_timestamp) / 1_000_000.0;
            log.info(.request, "<== 200 ({}), {d:.3} ms\n", .{ static_path, timestamp_in_ms });
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

const max_stack_file_read_size = 4_000_000;
const max_heap_file_read_size = 1_000_000_000_000;
