const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;
const log = std.log;
const process = std.process;
const debug = std.debug;
const builtin = std.builtin;

const network = @import("network");

const parsing = @import("./parsing.zig");

const ArrayList = std.ArrayList;
const Socket = network.Socket;
const SocketSet = network.SocketSet;
const EndPoint = network.EndPoint;

const debug_prints = false;

pub const log_level = .info;

const Connection = union(enum) {
    none: void,
    receiving: ReceivingState,
    sending: SendingState,
};

const ReceivingState = struct {
    socket: Socket,
    endpoint: EndPoint,
};

const SendingState = struct {
    const Self = @This();

    file: fs.File,
    file_length: usize,
    position: usize,
    socket: Socket,
    endpoint: EndPoint,
    etag: u32,
    arena: heap.ArenaAllocator,
    static_path: []const u8,
    request: parsing.Request,
    start_timestamp: i128,
    headers_sent: bool = false,

    leak_detecting_allocator: ?testing.LeakCountAllocator = null,

    pub fn sendChunk(
        self: *Self,
        allocator: *mem.Allocator,
        socket_set: *SocketSet,
        chunk_size: usize,
    ) !Connection {
        var buffer = try allocator.alloc(u8, chunk_size);

        const read_bytes = try self.file.read(buffer);
        const send_buffer = buffer[0..read_bytes];
        var sent_bytes = try self.socket.send(send_buffer);

        // debug.print(
        //     "send_buffer={}\n\tread_bytes={}\tbuffer.len={}\tsent_bytes={}\tfile.pos={}\n",
        //     .{
        //         send_buffer,
        //         read_bytes,
        //         buffer.len,
        //         sent_bytes,
        //         self.file.getPos() catch unreachable,
        //     },
        // );

        if (read_bytes < buffer.len) {
            const end_timestamp = std.time.nanoTimestamp();
            const timestamp_in_ms = @intToFloat(f64, end_timestamp - self.start_timestamp) / 1_000_000.0;
            log.info(
                .send,
                "{} <== {} ({d:.3} ms)\n",
                .{ self.endpoint, self.static_path, timestamp_in_ms },
            );
            self.deinit(socket_set);
            if (self.leak_detecting_allocator) |lda| {
                try lda.validate();
            }

            return Connection.none;
        } else {
            self.position += read_bytes;

            return Connection{ .sending = self.* };
        }
    }

    pub fn deinit(self: *Self, socket_set: *SocketSet) void {
        self.arena.deinit();
        self.socket.close();
        self.file.close();
        socket_set.remove(self.socket);
    }
};

pub fn main() anyerror!void {
    try network.init();
    defer network.deinit();

    const arguments = try process.argsAlloc(heap.page_allocator);
    const process_name = arguments[0];
    if (arguments.len < 2) {
        log.err(.arguments, "Usage: {} <chunk_size>\n", .{process_name});

        process.exit(1);
    }
    const chunk_size = try fmt.parseInt(usize, arguments[1], 10);

    const endpoint = network.EndPoint{
        .address = network.Address{
            .ipv4 = .{
                .value = [_]u8{ 0, 0, 0, 0 },
            },
        },
        .port = 80,
    };

    const socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.tcp);
    var socket_set = try SocketSet.init(heap.page_allocator);
    defer socket_set.deinit();
    var connections = ArrayList(Connection).init(heap.page_allocator);
    try socket.bind(endpoint);
    try socket.listen();
    defer socket.close();
    if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
        try socket.enablePortReuse(true);
    }
    try socket_set.add(socket, .{ .read = true, .write = true });

    var memory_buffer: [max_stack_file_read_size]u8 = undefined;
    var fixed_buffer_allocator = heap.FixedBufferAllocator.init(&memory_buffer);
    var request_stack_allocator = &fixed_buffer_allocator.allocator;

    while (true) {
        _ = network.waitForSocketEvent(&socket_set, 10_000_000_000_000) catch |e| {
            if (builtin.os.tag == .windows) {
                switch (e) {
                    error.FileDescriptorNotASocket => {
                        debug.print("===== ERROR socket_set={}\n", .{socket_set});
                        for (connections.items) |connection, i| {
                            debug.print("===== ERROR connection{}={}\n", .{ i, connection });
                        }
                        process.exit(1);
                    },
                    error.OutOfMemory => {},
                    error.Unexpected => {},
                }
            } else {
                switch (e) {
                    error.SystemResources, error.Unexpected => unreachable,
                }
            }
        };
        if (socket_set.isReadyRead(socket)) {
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
            try socket_set.add(client_socket, .{ .read = true, .write = true });
            try insertIntoFirstFree(&connections, client_socket);
        }

        const local_endpoint = try socket.getLocalEndPoint();

        if (debug_prints) {
            debug.print("===== connections.capacity={}\n", .{connections.capacity});
            debug.print("===== connections.items.len={}\n", .{connections.items.len});
            for (connections.items) |c| {
                debug.print("\tc={}\n", .{c});
            }
        }

        for (connections.items) |*connection| {
            connection.* = try handleConnection(
                connection,
                request_stack_allocator,
                local_endpoint,
                &socket_set,
                chunk_size,
            );
            fixed_buffer_allocator.reset();
        }
    }
}

fn handleConnection(
    connection: *Connection,
    stack_allocator: *mem.Allocator,
    local_endpoint: EndPoint,
    socket_set: *SocketSet,
    send_chunk_size: usize,
) !Connection {
    var maybe_socket: ?Socket = switch (connection.*) {
        .receiving => |receiving| receiving.socket,
        .sending => |sending| sending.socket,
        .none => null,
    };

    if (maybe_socket) |s| {
        if (socket_set.isFaulted(s)) {
            s.close();
            socket_set.remove(s);

            return Connection.none;
        }
    }

    switch (connection.*) {
        .receiving => |receiving| {
            if (socket_set.isReadyRead(receiving.socket)) {
                const start_timestamp = std.time.nanoTimestamp();
                var arena = heap.ArenaAllocator.init(heap.page_allocator);
                errdefer arena.deinit();
                var request_arena_allocator = &arena.allocator;
                const remote_endpoint = receiving.endpoint;
                const socket = receiving.socket;
                var buffer = try stack_allocator.alloc(u8, 2056);
                var received = socket.receive(buffer[0..]) catch |e| {
                    log.err(.receive, "=== receive error 1 ===\n", .{});

                    socket.close();
                    socket_set.remove(socket);

                    return Connection.none;
                };
                const request = parsing.Request.fromSlice(
                    request_arena_allocator,
                    buffer[0..received],
                ) catch |e| {
                    switch (e) {
                        error.OutOfMemory => {
                            _ = try socket.send(high_load_response);
                            socket.close();
                            socket_set.remove(socket);

                            return Connection.none;
                        },
                        error.InvalidCharacter,
                        error.UnableToParseConnectionStatus,
                        error.UnableToparseCacheControlValue,
                        error.UnableToparseCacheControlHeader,
                        error.UnableToParseWeakETagValue,
                        error.UnableToParseNormalETagValue,
                        error.UnableToParseETag,
                        error.UnableToParseCrossOriginResourcePolicy,
                        error.UnableToParseMethod,
                        error.UnableToParseAllowCredentials,
                        error.UnableToParseScheme,
                        error.UnableToParseOriginScheme,
                        error.UnableToFindHeaderSeparator,
                        error.UnableToParseVersion,
                        error.NoVersionGiven,
                        error.NoResourceGiven,
                        error.NoMethodGiven,
                        => {
                            _ = try socket.send(bad_request_response);
                            socket.close();
                            socket_set.remove(socket);

                            return Connection.none;
                        },
                        error.Overflow => {
                            _ = try socket.send(internal_error_response);
                            socket.close();
                            socket_set.remove(socket);

                            return Connection.none;
                        },
                    }
                };
                errdefer request.deinit();

                if (request.request_line.method == .get) {
                    const resource_slice = request.request_line.resourceSlice()[1..];
                    const resource = if (mem.eql(u8, resource_slice, "")) "index.html" else resource_slice;
                    const static_path = try mem.concat(
                        request_arena_allocator,
                        u8,
                        &[_][]const u8{ "static/", resource },
                    );
                    errdefer request_arena_allocator.free(static_path);

                    log.info(
                        .request,
                        "{} ==> {} {}\n",
                        .{ remote_endpoint, request.request_line.method.toSlice(), static_path },
                    );

                    const file = fs.cwd().openFile(static_path, .{}) catch |e| {
                        switch (e) {
                            error.FileNotFound => {
                                _ = socket.send(not_found_response) catch |send_error| {
                                    log.err(.send, "=== send error 404 ===\n", .{});
                                };
                                log.err(
                                    .file,
                                    "{} <== {} 404 ({})\n",
                                    .{ remote_endpoint, local_endpoint, static_path },
                                );

                                socket.close();
                                socket_set.remove(socket);

                                return Connection.none;
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
                                _ = socket.send(internal_error_response) catch
                                    |send_error| {
                                    log.err(.send, "=== send error 500 ===\n", .{});
                                };
                                log.err(
                                    .unexpected,
                                    "{} <== {} 500 ({}) ({})\n",
                                    .{ remote_endpoint, local_endpoint, static_path, e },
                                );

                                socket.close();
                                socket_set.remove(socket);
                                request.deinit();

                                return Connection.none;
                            },
                        }
                    };

                    const stat = try file.stat();
                    const last_modification_time = stat.mtime;
                    const expected_file_size = stat.size;

                    const hash_function = std.hash_map.getAutoHashFn(@TypeOf(last_modification_time));
                    const etag = hash_function(last_modification_time);
                    var if_none_match_request_header: ?parsing.Header = null;
                    for (request.headers.items) |h| {
                        switch (h) {
                            .if_none_match => |d| if_none_match_request_header = h,
                            else => {},
                        }
                    }
                    if (if_none_match_request_header) |h| {
                        const etag_value = fmt.parseInt(
                            u32,
                            h.if_none_match,
                            10,
                        ) catch |e| etag_value: {
                            log.err(
                                .etag,
                                "|== Unable to hash incoming etag value: {}\n",
                                .{h.if_none_match},
                            );

                            break :etag_value 0;
                        };
                        if (etag_value == etag) {
                            log.info(
                                .response,
                                "{} <== {} (304 via ETag)\n",
                                .{ remote_endpoint, static_path },
                            );
                            _ = try socket.send(not_modified_response);

                            socket.close();
                            socket_set.remove(socket);

                            return Connection.none;
                        }
                    }

                    const sending = Connection{
                        .sending = SendingState{
                            .socket = socket,
                            .file = file,
                            .file_length = expected_file_size,
                            .position = 0,
                            .etag = etag,
                            .endpoint = remote_endpoint,
                            .arena = arena,
                            .static_path = static_path,
                            .request = request,
                            .start_timestamp = start_timestamp,
                            .leak_detecting_allocator = lda,
                        },
                    };

                    return sending;
                } else {
                    socket_set.remove(socket);
                    socket.close();
                    request.deinit();

                    return Connection.none;
                }
            }

            return connection.*;
        },

        .sending => |*sending| {
            const socket = sending.socket;
            if (socket_set.isReadyWrite(socket)) {
                if (!sending.headers_sent) {
                    _ = socket.send("HTTP/1.1 200 OK\n") catch unreachable;
                    var header_buffer = try stack_allocator.alloc(u8, 128);
                    const etag_header = try fmt.bufPrint(header_buffer, "ETag: {}\n", .{sending.etag});
                    _ = socket.send(etag_header) catch unreachable;
                    const content_type_header = try fmt.bufPrint(
                        header_buffer,
                        "Content-type: {}\n",
                        .{determineContentType(sending.static_path)},
                    );
                    _ = socket.send(content_type_header) catch unreachable;
                    _ = socket.send("\n") catch unreachable;

                    sending.headers_sent = true;
                }
                const next_state = sending.sendChunk(
                    stack_allocator,
                    socket_set,
                    send_chunk_size,
                ) catch |e| new_state: {
                    switch (e) {
                        error.OutOfMemory => {
                            log.err(.send, "OOM!\n", .{});
                        },
                        error.Leak => unreachable,
                        error.ConnectionTimedOut,
                        error.ConnectionResetByPeer,
                        error.BrokenPipe,
                        error.OperationAborted,
                        => {
                            log.err(
                                .send,
                                "Broken pipe / ConnectionResetByPeer sending to {}\n",
                                .{sending.endpoint},
                            );
                        },
                        error.IsDir,
                        error.AccessDenied,
                        error.WouldBlock,
                        error.FastOpenAlreadyInProgress,
                        error.MessageTooBig,
                        error.SystemResources,
                        error.InputOutput,
                        error.Unexpected,
                        => {
                            debug.panic("odd error: {}\n", .{e});
                        },
                    }

                    sending.deinit(socket_set);

                    return Connection.none;
                };

                return next_state;
            } else {
                return connection.*;
            }
        },
        .none => return Connection.none,
    }
}

fn insertIntoFirstFree(
    connections: *ArrayList(Connection),
    socket: Socket,
) !void {
    var found_slot = false;
    const endpoint = try socket.getRemoteEndPoint();
    const receiving_state = ReceivingState{ .socket = socket, .endpoint = endpoint };

    for (connections.items) |*connection, i| {
        switch (connection.*) {
            .none => {
                connection.* = Connection{ .receiving = receiving_state };
                found_slot = true;
                break;
            },
            .receiving, .sending => {},
        }
    }

    if (!found_slot) try connections.append(Connection{ .receiving = receiving_state });
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
    else if (mem.endsWith(u8, path, ".mp4"))
        "video/mp4"
    else if (mem.endsWith(u8, path, ".mkv"))
        "video/x-matroska"
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

const bad_request_response =
    \\HTTP/1.1 400 Bad Request
    \\Content-length: 11
    \\
    \\Bad request
;

const internal_error_response =
    \\500 Internal Server Error
    \\Content-length: 21
    \\
    \\Internal Server Error
;
