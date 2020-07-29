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
const builtin = std.builtin;

const network = @import("network");

const parsing = @import("./parsing.zig");

pub const log_level = .info;

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

    const socket = try network.Socket.create(network.AddressFamily.ipv4, network.Protocol.tcp);
    try socket.bind(endpoint);
    try socket.listen();
    if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
        try socket.enablePortReuse(true);
    }

    while (true) {
        const client_socket = socket.accept() catch |e| {
            switch (e) {
                error.ConnectionAborted => {
                    log.err(.accept, "Client aborted connection\n", .{});

                    continue;
                },

                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                error.SystemResources,
                error.UnsupportedAddressFamily,
                error.ProtocolFailure,
                error.BlockedByFirewall,
                error.WouldBlock,
                error.PermissionDenied,
                error.Unexpected,
                => {
                    continue;
                },
            }
        };
        _ = Thread.spawn(client_socket, handleRequest) catch |e| {
            switch (e) {
                error.OutOfMemory,
                error.ThreadQuotaExceeded,
                error.SystemResources,
                error.LockedMemoryLimitExceeded,
                => {
                    _ = try client_socket.send(high_load_response);
                },
                error.Unexpected => {
                    log.err(.spawn, "Unexpected error when trying to create thread.\n", .{});
                    _ = try client_socket.send(internal_error_response);
                },
            }
        };
    }
}

fn handleRequest(client_socket: network.Socket) !void {
    var memory_buffer: [max_stack_file_read_size]u8 = undefined;
    var fixed_buffer_allocator = heap.FixedBufferAllocator.init(&memory_buffer);
    var request_stack_allocator = &fixed_buffer_allocator.allocator;
    defer fixed_buffer_allocator.reset();

    var client_socket_open = true;
    const start_timestamp = std.time.nanoTimestamp();

    const local_endpoint = client_socket.getLocalEndPoint() catch |e| {
        switch (e) {
            error.UnsupportedAddressFamily => {
                log.err(.endpoint, "|== Client connected with unsupported address family\n", .{});

                client_socket.close();
                return;
            },
            error.InsufficientBytes, error.SystemResources, error.Unexpected => {
                log.err(
                    .endpoint,
                    "|== Unexpected error for client endpoint discovery: {}\n",
                    .{e},
                );

                client_socket.close();
                return;
            },
        }
    };

    const remote_endpoint = client_socket.getRemoteEndPoint() catch |e| {
        switch (e) {
            error.NotConnected => {
                log.err(.endpoint, "|== Client disconnected before endpoint discovery\n", .{});

                client_socket.close();
                return;
            },
            error.UnsupportedAddressFamily => {
                log.err(.endpoint, "|== Client connected with unsupported address family\n", .{});

                client_socket.close();
                return;
            },
            error.InsufficientBytes, error.SystemResources, error.Unexpected => {
                log.err(
                    .endpoint,
                    "|== Unexpected error for client endpoint discovery: {}\n",
                    .{e},
                );

                client_socket.close();
                return;
            },
        }
    };

    var buffer = try request_stack_allocator.alloc(u8, 2056);
    var received = client_socket.receive(buffer[0..]) catch |e| {
        log.err(.receive, "=== receive error 1 ===\n", .{});

        return;
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

        log.info(
            .request,
            "{} ==> {} {}\n",
            .{ remote_endpoint, request.request_line.method.toSlice(), static_path },
        );

        const file_descriptor = fs.cwd().openFile(static_path, .{}) catch |e| {
            switch (e) {
                error.FileNotFound => {
                    _ = client_socket.send(not_found_response) catch |send_error| {
                        log.err(.send, "=== send error 404 ===\n", .{});
                    };
                    log.err(
                        .file,
                        "{} <== {} 404 ({})\n",
                        .{ remote_endpoint, local_endpoint, static_path },
                    );
                    client_socket.close();

                    return;
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
                    _ = client_socket.send(internal_error_response) catch
                        |send_error| {
                        log.err(.send, "=== send error 500 ===\n", .{});
                    };
                    log.err(
                        .unexpected,
                        "{} <== {} 500 ({}) ({})\n",
                        .{ remote_endpoint, local_endpoint, static_path, e },
                    );

                    return;
                },
            }
        };

        const stat = try file_descriptor.stat();
        const last_modification_time = stat.mtime;
        const expected_file_size = stat.size;

        const hash_function = std.hash_map.getAutoHashFn(@TypeOf(last_modification_time));
        const etag_hash = hash_function(last_modification_time);
        var if_none_match_request_header: ?parsing.Header = null;
        for (request.headers.items) |h| {
            switch (h) {
                .if_none_match => |d| if_none_match_request_header = h,
                else => {},
            }
        }
        if (if_none_match_request_header) |h| {
            const etag_value = fmt.parseInt(u32, h.if_none_match, 10) catch |e| etag_value: {
                log.err(.etag, "|== Unable to hash incoming etag value: {}\n", .{h.if_none_match});

                break :etag_value 0;
            };
            if (etag_value == etag_hash) {
                log.info(
                    .response,
                    "{} <== {} 304 ({})\n",
                    .{ remote_endpoint, local_endpoint, static_path },
                );
                _ = try client_socket.send(not_modified_response);
                client_socket.close();

                return;
            }
        }

        _ = client_socket.send("HTTP/1.1 200 OK\n") catch unreachable;
        var header_buffer = try request_stack_allocator.alloc(u8, 128);
        const etag_header = try fmt.bufPrint(
            header_buffer,
            "ETag: {}\n",
            .{etag_hash},
        );
        _ = client_socket.send(etag_header) catch unreachable;
        const content_type_header = try fmt.bufPrint(
            header_buffer,
            "Content-type: {}\n",
            .{determineContentType(static_path)},
        );
        _ = client_socket.send(content_type_header) catch unreachable;
        _ = client_socket.send("\n") catch unreachable;

        var file_buffer = try request_stack_allocator.alloc(u8, max_stack_file_read_size - 100_000);
        var read_bytes = try file_descriptor.read(file_buffer);
        while (read_bytes == file_buffer.len) : (read_bytes = try file_descriptor.read(file_buffer)) {
            _ = client_socket.send(file_buffer) catch |e| {
                switch (e) {
                    error.ConnectionResetByPeer, error.BrokenPipe => {
                        log.err(
                            .send,
                            "Broken pipe / ConnectionResetByPeer sending to {}\n",
                            .{try (client_socket.getRemoteEndPoint())},
                        );
                    },
                    error.AccessDenied,
                    error.WouldBlock,
                    error.FastOpenAlreadyInProgress,
                    error.MessageTooBig,
                    error.SystemResources,
                    error.Unexpected,
                    => {
                        debug.panic("odd error: {}\n", .{e});
                    },
                }
                client_socket.close();
                client_socket_open = false;
                break;
            };
        }
        if (client_socket_open) {
            _ = client_socket.send(file_buffer[0..read_bytes]) catch |e| {};
            _ = client_socket.send("\n\n") catch unreachable;

            const end_timestamp = std.time.nanoTimestamp();
            const timestamp_in_ms = @intToFloat(f64, end_timestamp - start_timestamp) / 1_000_000.0;
            log.info(
                .request,
                "{} <== {} 200 ({}), {d:.3} ms\n",
                .{ remote_endpoint, local_endpoint, static_path, timestamp_in_ms },
            );
            client_socket.close();
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
    else if (mem.endsWith(u8, path, ".css"))
        "text/css"
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

const max_stack_file_read_size = 4_000_000;
const max_heap_file_read_size = 1_000_000_000_000;

const not_found_response =
    \\HTTP/1.1 404 Not found
    \\Content-length: 14
    \\
    \\File not found
;

const not_modified_response =
    \\HTTP/1.1 304 Not modified
    \\
;

const high_load_response =
    \\HTTP/1.1 503 Busy
    \\Content-length: 13
    \\
    \\Load too high
;

const internal_error_response =
    \\500 Internal Server Error
    \\Content-length: 21
    \\
    \\Internal Server Error
;
