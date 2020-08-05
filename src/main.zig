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
    idle: void,
    receiving: ReceivingState,
    sending: SendingState,
};

const ReceivingState = struct {
    socket: Socket,
    endpoint: EndPoint,
    start_timestamp: i128,
};

const SendingState = struct {
    const Self = @This();

    file: fs.File,
    file_length: usize,
    position: usize,
    socket: Socket,
    endpoint: EndPoint,
    etag: u32,
    arena: *heap.ArenaAllocator,
    static_path: []const u8,
    request: parsing.Request,
    start_timestamp: i128,
    headers_sent: bool = false,

    longtime_allocator: *mem.Allocator,
    leak_detecting_allocator: ?*testing.LeakCountAllocator = null,

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
            try self.deinit(socket_set);

            return Connection.idle;
        } else {
            self.position += read_bytes;

            return Connection{ .sending = self.* };
        }
    }

    pub fn deinit(self: *Self, socket_set: *SocketSet) !void {
        // self.request.deinit();
        self.arena.deinit();
        if (self.leak_detecting_allocator) |lda| {
            try lda.validate();
            self.longtime_allocator.destroy(lda);
        }

        self.longtime_allocator.destroy(self.arena);
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
    if (arguments.len < 3) {
        log.err(.arguments, "Usage: {} <chunk_size> <static_root>\n", .{process_name});

        process.exit(1);
    }

    const chunk_size = try fmt.parseInt(usize, arguments[1], 10);
    const static_root = if (!mem.endsWith(u8, arguments[2], "/"))
        try mem.concat(heap.page_allocator, u8, &[_][]const u8{ arguments[2], "/" })
    else
        try heap.page_allocator.dupe(u8, arguments[2]);

    var memory_debug = false;
    for (arguments) |argument| {
        if (mem.eql(u8, argument, "memory-debug")) {
            memory_debug = true;

            break;
        }
    }

    process.argsFree(heap.page_allocator, arguments);

    const endpoint = network.EndPoint{
        .address = network.Address{ .ipv4 = .{ .value = [_]u8{ 0, 0, 0, 0 } } },
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
    var logging_allocator = heap.loggingAllocator(heap.page_allocator, std.io.getStdOut().writer());

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
                if (memory_debug) &logging_allocator.allocator else heap.page_allocator,
                local_endpoint,
                &socket_set,
                chunk_size,
                memory_debug,
                connections,
                static_root,
            );
            fixed_buffer_allocator.reset();
        }
    }
}

fn removeFaultedReceivingSocket(receiving: ReceivingState, socket_set: *SocketSet) bool {
    if (socket_set.isFaulted(receiving.socket)) {
        socket_set.remove(receiving.socket);
        receiving.socket.close();

        return true;
    }

    return false;
}

fn removeFaultedSendingSocket(sending: *SendingState, socket_set: *SocketSet) !bool {
    if (socket_set.isFaulted(sending.socket)) {
        try sending.deinit(socket_set);

        return true;
    }

    return false;
}

fn handleConnection(
    connection: *Connection,
    stack_allocator: *mem.Allocator,
    longtime_allocator: *mem.Allocator,
    local_endpoint: EndPoint,
    socket_set: *SocketSet,
    send_chunk_size: usize,
    memory_debug: bool,
    connections: ArrayList(Connection),
    static_root: []const u8,
) !Connection {
    const socket_is_faulted = switch (connection.*) {
        .receiving => |receiving| removeFaultedReceivingSocket(receiving, socket_set),
        .sending => |*sending| removeFaultedSendingSocket(sending, socket_set) catch |e| {
            switch (e) {
                // blow up here intentionally, we're running with a leak detecting allocator
                error.Leak => unreachable,
            }
        },
        .idle => false,
    };

    if (socket_is_faulted) return Connection.idle;

    switch (connection.*) {
        .receiving => |receiving| {
            const timestamp = std.time.nanoTimestamp();

            if ((timestamp - receiving.start_timestamp) > 30_000_000_000) {
                socket_set.remove(receiving.socket);
                receiving.socket.close();

                return Connection.idle;
            } else if (socket_set.isReadyRead(receiving.socket)) {
                var lda: ?*testing.LeakCountAllocator = null;
                if (memory_debug) {
                    lda = try longtime_allocator.create(testing.LeakCountAllocator);
                    lda.?.* = testing.LeakCountAllocator.init(longtime_allocator);
                }
                var arena = try longtime_allocator.create(heap.ArenaAllocator);
                if (lda) |l| {
                    arena.* = heap.ArenaAllocator.init(&l.allocator);
                } else {
                    arena.* = heap.ArenaAllocator.init(longtime_allocator);
                }
                errdefer arena.deinit();
                var request_arena_allocator = &arena.allocator;

                const remote_endpoint = receiving.endpoint;
                const socket = receiving.socket;
                var buffer = try stack_allocator.alloc(u8, 2056);
                var received = socket.receive(buffer[0..]) catch |e| {
                    log.err(.receive, "=== receive error 1 ===\n", .{});

                    socket.close();
                    socket_set.remove(socket);

                    return Connection.idle;
                };

                const request = parsing.Request.fromSlice(
                    request_arena_allocator,
                    buffer[0..received],
                ) catch |parsing_error| {
                    arena.deinit();
                    longtime_allocator.destroy(arena);
                    if (lda) |a| longtime_allocator.destroy(a);
                    socket_set.remove(socket);
                    switch (parsing_error) {
                        error.OutOfMemory => {
                            _ = socket.send(high_load_response) catch |send_error| {
                                log.err(
                                    .parsing,
                                    "{} <== OOM error send error: {}\n",
                                    .{ remote_endpoint, send_error },
                                );
                            };
                            socket.close();

                            return Connection.idle;
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
                            log.err(
                                .parsing,
                                "{} <== 400 Bad Request: {}\n",
                                .{ remote_endpoint, parsing_error },
                            );
                            _ = socket.send(bad_request_response) catch |send_error| {
                                log.err(
                                    .parsing,
                                    "{} <== 400 Bad Request send error\n",
                                    .{remote_endpoint},
                                );
                            };
                            socket.close();

                            return Connection.idle;
                        },
                        error.Overflow => {
                            log.err(
                                .parsing,
                                "{} <== 500 Internal error: Overflow\n",
                                .{remote_endpoint},
                            );
                            _ = socket.send(internal_error_response) catch |send_error| {
                                log.err(
                                    .parsing,
                                    "{} <== 500 Internal error send error: {}\n",
                                    .{ remote_endpoint, send_error },
                                );
                            };
                            socket.close();

                            return Connection.idle;
                        },
                    }
                };

                const resource_slice = request.request_line.resourceSlice()[1..];
                const resource = if (mem.eql(u8, resource_slice, "")) "index.html" else resource_slice;

                if (request.request_line.method == .get and mem.eql(u8, resource, "diagnostics")) {
                    const content_format =
                        \\Connections: {}
                        \\
                    ;

                    var content = fmt.allocPrint(
                        stack_allocator,
                        content_format,
                        .{connections.items.len},
                    ) catch |alloc_print_error| {
                        switch (alloc_print_error) {
                            error.OutOfMemory => {
                                log.err(
                                    .diagnostics,
                                    "Unable to allocate memory for diagnostics content.\n",
                                    .{},
                                );

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                longtime_allocator.destroy(arena);
                                if (lda) |a| longtime_allocator.destroy(a);

                                return Connection.idle;
                            },
                        }
                    };
                    for (connections.items) |c| {
                        const connection_info = switch (c) {
                            .receiving => |r| try fmt.allocPrint(
                                stack_allocator,
                                "R: {}\n",
                                .{r.endpoint},
                            ),
                            .sending => |s| connection_info: {
                                var string = try fmt.allocPrint(
                                    stack_allocator,
                                    "S: {} => {}\n",
                                    .{ s.static_path, s.endpoint },
                                );
                                for (s.request.headers.items) |h| {
                                    string = try mem.concat(
                                        stack_allocator,
                                        u8,
                                        &[_][]const u8{
                                            string,
                                            try fmt.allocPrint(stack_allocator, "\t{}\n", .{h}),
                                        },
                                    );
                                }
                                string = try mem.concat(stack_allocator, u8, &[_][]const u8{
                                    string,
                                    try fmt.allocPrint(stack_allocator, "\t{}\n", .{s.request.body}),
                                });

                                break :connection_info string;
                            },
                            .idle => "Idle\n",
                        };
                        content = mem.concat(
                            stack_allocator,
                            u8,
                            &[_][]const u8{ content, connection_info },
                        ) catch |concat_error| content: {
                            log.err(
                                .diagnostics,
                                "Concat error while adding '{}'\n",
                                .{connection_info},
                            );

                            break :content content;
                        };
                    }

                    const format =
                        \\HTTP/1.1 200 OK
                        \\Content-length: {}
                        \\Content-type: text/plain
                        \\
                        \\{}
                    ;
                    const response = try fmt.allocPrint(stack_allocator, format, .{ content.len, content });

                    _ = socket.send(response) catch |send_error| {
                        log.err(.diagnostics, "=== Diagnostics send error: {}\n", .{send_error});
                    };

                    socket.close();
                    socket_set.remove(socket);
                    arena.deinit();
                    longtime_allocator.destroy(arena);
                    if (lda) |a| longtime_allocator.destroy(a);

                    return Connection.idle;
                } else if (request.request_line.method == .get) {
                    const static_path = mem.concat(
                        request_arena_allocator,
                        u8,
                        &[_][]const u8{ static_root, resource },
                    ) catch |concat_error| {
                        switch (concat_error) {
                            error.OutOfMemory => {
                                log.err(
                                    .static_path,
                                    "=== OOM while concatting static path: {}\n",
                                    .{resource},
                                );
                                _ = socket.send(high_load_response) catch |send_error| {
                                    log.err(
                                        .static_path,
                                        "=== High load / OOM send error: {}\n",
                                        .{send_error},
                                    );
                                };

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                if (lda) |a| longtime_allocator.destroy(a);
                                longtime_allocator.destroy(arena);

                                return Connection.idle;
                            },
                        }
                    };
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
                                    log.err(.send, "=== send error 404 {} ===\n", .{send_error});
                                };
                                log.err(
                                    .file,
                                    "{} <== 404 ({})\n",
                                    .{ remote_endpoint, static_path },
                                );

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                if (lda) |a| longtime_allocator.destroy(a);
                                longtime_allocator.destroy(arena);

                                return Connection.idle;
                            },

                            error.NameTooLong => {
                                _ = socket.send(name_too_long_response) catch |send_error| {
                                    log.err(.send, "=== send error 500 {} ===\n", .{send_error});
                                };
                                log.err(
                                    .file,
                                    "{} <== 400 (Name too long, {})\n",
                                    .{ remote_endpoint, static_path },
                                );

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                if (lda) |a| longtime_allocator.destroy(a);
                                longtime_allocator.destroy(arena);

                                return Connection.idle;
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
                                _ = socket.send(internal_error_response) catch |send_error| {
                                    log.err(.send, "=== send error 500: {} ===\n", .{send_error});
                                };
                                log.err(
                                    .unexpected,
                                    "{} <== 500 ({}) ({})\n",
                                    .{ remote_endpoint, static_path, e },
                                );

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                if (lda) |a| longtime_allocator.destroy(a);
                                longtime_allocator.destroy(arena);

                                return Connection.idle;
                            },
                        }
                    };

                    const stat = file.stat() catch |stat_error| {
                        switch (stat_error) {
                            error.AccessDenied => {
                                _ = socket.send(not_found_response) catch |send_error| {
                                    log.err(.send, "=== send error 404 {} ===\n", .{send_error});
                                };
                                log.err(
                                    .stat,
                                    "{} <== 404 ({})\n",
                                    .{ remote_endpoint, static_path },
                                );

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                if (lda) |a| longtime_allocator.destroy(a);
                                longtime_allocator.destroy(arena);

                                return Connection.idle;
                            },
                            error.SystemResources, error.Unexpected => {
                                _ = socket.send(internal_error_response) catch |send_error| {
                                    log.err(.send, "=== send error 500: {} ===\n", .{send_error});
                                };
                                log.err(
                                    .stat,
                                    "{} <== 500 ({}) ({})\n",
                                    .{ remote_endpoint, static_path, stat_error },
                                );

                                socket.close();
                                socket_set.remove(socket);
                                arena.deinit();
                                if (lda) |a| longtime_allocator.destroy(a);
                                longtime_allocator.destroy(arena);

                                return Connection.idle;
                            },
                        }
                    };
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
                            _ = socket.send(not_modified_response) catch |send_error| {
                                log.err(
                                    .etag,
                                    "{} <== 304 not modified send error: {}\n",
                                    .{ remote_endpoint, send_error },
                                );
                            };

                            socket.close();
                            socket_set.remove(socket);
                            arena.deinit();
                            longtime_allocator.destroy(arena);
                            if (lda) |a| longtime_allocator.destroy(a);

                            return Connection.idle;
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
                            .start_timestamp = timestamp,
                            .leak_detecting_allocator = lda,
                            .longtime_allocator = longtime_allocator,
                        },
                    };

                    return sending;
                } else {
                    _ = socket.send(method_not_allowed_response) catch |send_error| {
                        log.err(
                            .send,
                            "{} <== Method not allowed send error: {}\n",
                            .{ remote_endpoint, send_error },
                        );
                    };

                    log.info(
                        .response,
                        "{} <== 405 Method Not Allowed: {}\n",
                        .{ remote_endpoint, request.request_line.method },
                    );

                    socket_set.remove(socket);
                    socket.close();
                    arena.deinit();
                    longtime_allocator.destroy(arena);
                    if (lda) |a| {
                        longtime_allocator.destroy(a);
                    }

                    return Connection.idle;
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

                    try sending.deinit(socket_set);

                    return Connection.idle;
                };

                return next_state;
            } else {
                return connection.*;
            }
        },
        .idle => return Connection.idle,
    }
}

fn insertIntoFirstFree(connections: *ArrayList(Connection), socket: Socket) !void {
    const timestamp = std.time.nanoTimestamp();
    var found_slot = false;
    const endpoint = try socket.getRemoteEndPoint();
    const receiving_state = ReceivingState{
        .socket = socket,
        .endpoint = endpoint,
        .start_timestamp = timestamp,
    };

    for (connections.items) |*connection, i| {
        switch (connection.*) {
            .idle => {
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

const method_not_allowed_response =
    \\HTTP/1.1 405 Method Not Allowed
    \\Content-length: 18
    \\
    \\Method not allowed
;

const name_too_long_response =
    \\HTTP/1.1 400 Bad Request
    \\Content-length: 45
    \\
    \\Bad request, name too long for this server :(
;

const internal_error_response =
    \\HTTP/1.1 500 Internal Server Error
    \\Content-length: 21
    \\
    \\Internal Server Error
;
