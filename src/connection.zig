const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;
const log = std.log;

const network = @import("network");
const parsing = @import("./parsing.zig");
const example_data = @import("./example_data.zig");
const ArrayList = std.ArrayList;
const Socket = network.Socket;
const EndPoint = network.EndPoint;
const SocketSet = network.SocketSet;

const Etag = u64;

pub const Connection = union(enum) {
    idle: void,
    receiving: ReceivingState,
    sending: SendingState,

    pub fn sendingFile(
        file: fs.File,
        file_length: usize,
        socket: Socket,
        endpoint: EndPoint,
        etag: Etag,
        arena: *heap.ArenaAllocator,
        static_path: []const u8,
        request: parsing.Request,
        longlived_allocator: *mem.Allocator,
    ) Connection {
        return Connection{
            .sending = SendingState{
                .socket = socket,
                .payload = Payload{
                    .file = FileInformation{
                        .file = file,
                        .file_length = file_length,
                        .etag = etag,
                        .static_path = static_path,
                    },
                },
                .endpoint = endpoint,
                .arena = arena,
                .request = request,
                .start_timestamp = std.time.nanoTimestamp(),
                .longlived_allocator = longlived_allocator,
                .headers_sent = false,
            },
        };
    }

    pub fn sendingData(
        data: []const u8,
        content_type: []const u8,
        allocator: *mem.Allocator,
        socket: Socket,
        endpoint: EndPoint,
        arena: *heap.ArenaAllocator,
        request: parsing.Request,
        longlived_allocator: *mem.Allocator,
    ) Connection {
        return Connection{
            .sending = SendingState{
                .socket = socket,
                .payload = Payload{
                    .data = DataInformation{
                        .data = data,
                        .content_type = content_type,
                        .position = 0,
                        .allocator = allocator,
                    },
                },
                .endpoint = endpoint,
                .arena = arena,
                .start_timestamp = std.time.nanoTimestamp(),
                .request = request,
                .headers_sent = false,
                .longlived_allocator = longlived_allocator,
            },
        };
    }

    pub fn receiving(socket: Socket, endpoint: EndPoint) Connection {
        return Connection{
            .receiving = ReceivingState{
                .socket = socket,
                .endpoint = endpoint,
                .start_timestamp = std.time.nanoTimestamp(),
            },
        };
    }
};

pub const ReceivingState = struct {
    socket: Socket,
    endpoint: EndPoint,
    start_timestamp: i128,
};

const FileInformation = struct {
    file: fs.File,
    file_length: usize,
    etag: Etag,
    static_path: []const u8,
};

const DataInformation = struct {
    data: []const u8,
    position: usize,
    allocator: *mem.Allocator,
    content_type: []const u8,
};

const Payload = union(enum) {
    file: FileInformation,
    data: DataInformation,
};

pub const SendingState = struct {
    const Self = @This();

    payload: Payload,
    socket: Socket,
    endpoint: EndPoint,
    arena: *heap.ArenaAllocator,
    request: parsing.Request,
    start_timestamp: i128,
    longlived_allocator: *mem.Allocator,
    headers_sent: bool = false,

    pub fn sendChunk(
        self: *Self,
        allocator: *mem.Allocator,
        socket_set: *SocketSet,
        chunk_size: usize,
    ) !Connection {
        const send_buffer = send_buffer: {
            switch (self.payload) {
                .file => |file_information| {
                    var file_buffer = try allocator.alloc(u8, chunk_size);
                    const read_bytes = try file_information.file.read(file_buffer);
                    break :send_buffer file_buffer[0..read_bytes];
                },
                .data => |*data_information| {
                    const position = data_information.position;
                    const data = data_information.data;
                    const data_buffer = if (position + chunk_size < data.len)
                        data[position..(position + chunk_size)]
                    else
                        data[position..];
                    data_information.position += data_buffer.len;

                    break :send_buffer data_buffer;
                },
            }
        };

        var sent_bytes = try self.socket.send(send_buffer);

        if (send_buffer.len < chunk_size) {
            const end_timestamp = std.time.nanoTimestamp();
            const time_difference = end_timestamp - self.start_timestamp;
            const timestamp_in_ms = @intToFloat(f64, time_difference) / 1_000_000.0;
            log.info(
                "{} <== {} ({d:.3} ms)",
                .{ self.endpoint, self.request.request_line.resource, timestamp_in_ms },
            );
            self.deinit(socket_set);

            return Connection.idle;
        } else {
            return Connection{ .sending = self.* };
        }
    }

    pub fn deinit(self: *Self, socket_set: *SocketSet) void {
        self.arena.deinit();
        self.longlived_allocator.destroy(self.arena);
        self.socket.close();
        switch (self.payload) {
            .file => |file_information| file_information.file.close(),
            .data => |data_information| data_information.allocator.free(data_information.data),
        }
        socket_set.remove(self.socket);
    }
};

pub fn handleConnection(
    connection: *Connection,
    stack_allocator: *mem.Allocator,
    longlived_allocator: *mem.Allocator,
    local_endpoint: EndPoint,
    socket_set: *SocketSet,
    send_chunk_size: usize,
    memory_debug: bool,
    connections: ArrayList(Connection),
    static_root: []const u8,
    running: *bool,
) !Connection {
    const socket_is_faulted = switch (connection.*) {
        .receiving => |receiving| removeFaultedReceivingSocket(receiving, socket_set),
        .sending => |*sending| removeFaultedSendingSocket(sending, socket_set),
        .idle => false,
    };

    if (socket_is_faulted) return Connection.idle;

    return switch (connection.*) {
        .receiving => |receiving| try handleReceiving(
            receiving,
            connection,
            longlived_allocator,
            stack_allocator,
            socket_set,
            connections,
            static_root,
            running,
            memory_debug,
        ),

        .sending => |*sending| try handleSending(
            sending,
            connection,
            socket_set,
            longlived_allocator,
            stack_allocator,
            send_chunk_size,
        ),
        .idle => Connection.idle,
    };
}

fn handleSending(
    sending: *SendingState,
    connection: *Connection,
    socket_set: *SocketSet,
    longlived_allocator: *mem.Allocator,
    stack_allocator: *mem.Allocator,
    send_chunk_size: usize,
) !Connection {
    const socket = sending.socket;
    if (socket_set.isReadyWrite(socket)) {
        if (!sending.headers_sent) {
            _ = socket.send("HTTP/1.1 200 OK\n") catch unreachable;
            var header_buffer = try stack_allocator.alloc(u8, 128);
            const etag_header = switch (sending.payload) {
                .file => |file_information| try fmt.bufPrint(
                    header_buffer,
                    "ETag: {}\n",
                    .{file_information.etag},
                ),
                .data => "",
            };
            _ = socket.send(etag_header) catch unreachable;

            const content_type = switch (sending.payload) {
                .file => |file_information| determineContentType(file_information.static_path),
                .data => |data_information| data_information.content_type,
            };
            const content_type_header = try fmt.bufPrint(
                header_buffer,
                "Content-type: {}\n",
                .{content_type},
            );
            _ = socket.send(content_type_header) catch unreachable;

            const content_length = switch (sending.payload) {
                .file => |file_information| file_information.file_length,
                .data => |data_information| data_information.data.len,
            };
            const content_length_header = try fmt.bufPrint(
                header_buffer,
                "Content-length: {}\n",
                .{content_length},
            );
            _ = socket.send(content_length_header) catch unreachable;

            _ = socket.send("\n") catch unreachable;

            sending.headers_sent = true;
        }
        const next_state = sending.sendChunk(
            stack_allocator,
            socket_set,
            send_chunk_size,
        ) catch |e| {
            switch (e) {
                error.OutOfMemory => {
                    log.err("OOM!", .{});
                },
                error.ConnectionTimedOut,
                error.ConnectionResetByPeer,
                error.BrokenPipe,
                error.OperationAborted,
                => {
                    log.err(
                        "Broken pipe / ConnectionResetByPeer sending to {}",
                        .{sending.endpoint},
                    );
                },
                error.FileDescriptorNotASocket,
                error.IsDir,
                error.AccessDenied,
                error.WouldBlock,
                error.FastOpenAlreadyInProgress,
                error.MessageTooBig,
                error.SystemResources,
                error.InputOutput,
                error.Unexpected,
                error.NotOpenForReading,
                => {
                    debug.panic("odd error: {}\n", .{e});
                },
            }

            sending.deinit(socket_set);

            return Connection.idle;
        };

        return next_state;
    } else {
        return connection.*;
    }
}

fn handleReceiving(
    receiving: ReceivingState,
    connection: *Connection,
    longlived_allocator: *mem.Allocator,
    stack_allocator: *mem.Allocator,
    socket_set: *SocketSet,
    connections: ArrayList(Connection),
    static_root: []const u8,
    running: *bool,
    memory_debug: bool,
) !Connection {
    const timestamp = std.time.nanoTimestamp();

    if ((timestamp - receiving.start_timestamp) > receiving_state_timeout) {
        socket_set.remove(receiving.socket);
        receiving.socket.close();

        return Connection.idle;
    } else if (socket_set.isReadyRead(receiving.socket)) {
        var arena = try longlived_allocator.create(heap.ArenaAllocator);
        arena.* = heap.ArenaAllocator.init(longlived_allocator);
        errdefer arena.deinit();
        var request_arena_allocator = &arena.allocator;

        const remote_endpoint = receiving.endpoint;
        const socket = receiving.socket;
        var buffer = try stack_allocator.alloc(u8, 2056);
        var received = socket.receive(buffer[0..]) catch |e| {
            log.err("=== receive error 1 ===", .{});

            socket.close();
            socket_set.remove(socket);

            return Connection.idle;
        };

        const request = parsing.Request.fromSlice(
            request_arena_allocator,
            buffer[0..received],
        ) catch |parsing_error| {
            arena.deinit();
            longlived_allocator.destroy(arena);
            socket_set.remove(socket);
            switch (parsing_error) {
                error.OutOfMemory => {
                    _ = socket.send(high_load_response) catch |send_error| {
                        log.err(
                            "{} <== OOM error send error: {}",
                            .{ remote_endpoint, send_error },
                        );
                    };
                    socket.close();

                    return Connection.idle;
                },
                error.InvalidCharacter,
                error.UnableToParseConnectionStatus,
                error.UnableToParseCacheControlValue,
                error.UnableToParseCacheControlHeader,
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
                        "{} <== 400 Bad Request: {}",
                        .{ remote_endpoint, parsing_error },
                    );
                    _ = socket.send(bad_request_response) catch |send_error| {
                        log.err(
                            "{} <== 400 Bad Request send error",
                            .{remote_endpoint},
                        );
                    };
                    socket.close();

                    return Connection.idle;
                },
                error.Overflow => {
                    log.err(
                        "{} <== 500 Internal error: Overflow",
                        .{remote_endpoint},
                    );
                    _ = socket.send(internal_error_response) catch |send_error| {
                        log.err(
                            "{} <== 500 Internal error send error: {}",
                            .{ remote_endpoint, send_error },
                        );
                    };
                    socket.close();

                    return Connection.idle;
                },
            }
        };

        const resource = if (mem.eql(u8, request.request_line.resource, ""))
            "index.html"
        else
            request.request_line.resource;

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
                            "Unable to allocate memory for diagnostics content.",
                            .{},
                        );

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

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
                            .{ s.request.request_line.resource, s.endpoint },
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
                        "Concat error while adding '{}'",
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
            const response = try fmt.allocPrint(
                stack_allocator,
                format,
                .{ content.len, content },
            );

            _ = socket.send(response) catch |send_error| {
                log.err("=== Diagnostics send error: {}", .{send_error});
            };

            socket.close();
            socket_set.remove(socket);
            arena.deinit();
            longlived_allocator.destroy(arena);

            return Connection.idle;
        } else if (request.request_line.method == .get) {
            // I think it's reasonable to error out completely here, given that the static directory
            // is pretty central to the whole thing. If it can't be opened it's closing time.
            var static_directory = try fs.cwd().openDir(static_root, .{});
            defer static_directory.close();

            const resource_is_directory = isDirectory(
                static_directory,
                request.request_line.resource,
            );

            // @TODO: Should probably redirect here to force trailing slash, so relative links work
            // properly?
            // `http://.../sub-directory` won't handle a relative link to `style.css` such that it
            // loads `http://.../sub-directory/style.css` for the implicitly loaded `index.html`.
            // This also needs to interact with any sanitation that the parser does for the resource
            // slice, which likely means it needs to use `trimLeft` instead of `trim`.

            const static_path_components = if (resource_is_directory)
                &[_][]const u8{ static_root, resource, "/index.html" }
            else
                &[_][]const u8{ static_root, resource };

            const static_path = mem.concat(
                request_arena_allocator,
                u8,
                static_path_components,
            ) catch |concat_error| {
                switch (concat_error) {
                    error.OutOfMemory => {
                        log.err(
                            "=== OOM while concatenating static path: {}",
                            .{resource},
                        );
                        _ = socket.send(high_load_response) catch |send_error| {
                            log.err(
                                "=== High load / OOM send error: {}\n",
                                .{send_error},
                            );
                        };

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

                        return Connection.idle;
                    },
                }
            };
            errdefer request_arena_allocator.free(static_path);

            log.info(
                "{} ==> {} {}",
                .{ remote_endpoint, request.request_line.method.toSlice(), static_path },
            );

            const file = fs.cwd().openFile(static_path, .{}) catch |e| {
                switch (e) {
                    error.FileNotFound => {
                        _ = socket.send(not_found_response) catch |send_error| {
                            log.err("=== send error 404 {} ===", .{send_error});
                        };
                        log.err(
                            "{} <== 404 ({})",
                            .{ remote_endpoint, static_path },
                        );

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

                        return Connection.idle;
                    },

                    error.NameTooLong => {
                        _ = socket.send(name_too_long_response) catch |send_error| {
                            log.err("=== send error 500 {} ===", .{send_error});
                        };
                        log.err(
                            "{} <== 400 (Name too long, {})",
                            .{ remote_endpoint, static_path },
                        );

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

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
                            log.err("=== send error 500: {} ===", .{send_error});
                        };
                        log.err(
                            "{} <== 500 ({}) ({})",
                            .{ remote_endpoint, static_path, e },
                        );

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

                        return Connection.idle;
                    },
                }
            };

            const stat = file.stat() catch |stat_error| {
                switch (stat_error) {
                    error.AccessDenied => {
                        _ = socket.send(not_found_response) catch |send_error| {
                            log.err("=== send error 404 {} ===", .{send_error});
                        };
                        log.err(
                            "{} <== 404 ({})",
                            .{ remote_endpoint, static_path },
                        );

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

                        return Connection.idle;
                    },
                    error.SystemResources, error.Unexpected => {
                        _ = socket.send(internal_error_response) catch |send_error| {
                            log.err("=== send error 500: {} ===", .{send_error});
                        };
                        log.err(
                            "{} <== 500 ({}) ({})",
                            .{ remote_endpoint, static_path, stat_error },
                        );

                        socket.close();
                        socket_set.remove(socket);
                        arena.deinit();
                        longlived_allocator.destroy(arena);

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
                    Etag,
                    h.if_none_match,
                    10,
                ) catch |e| etag_value: {
                    log.err(
                        "|== Unable to hash incoming etag value: {}",
                        .{h.if_none_match},
                    );

                    break :etag_value 0;
                };
                if (etag_value == etag) {
                    log.info(
                        "{} <== {} (304 via ETag)",
                        .{ remote_endpoint, static_path },
                    );
                    _ = socket.send(not_modified_response) catch |send_error| {
                        log.err(
                            "{} <== 304 not modified send error: {}",
                            .{ remote_endpoint, send_error },
                        );
                    };

                    socket.close();
                    socket_set.remove(socket);
                    arena.deinit();
                    longlived_allocator.destroy(arena);

                    return Connection.idle;
                }
            }

            return Connection.sendingFile(
                file,
                expected_file_size,
                socket,
                remote_endpoint,
                etag,
                arena,
                static_path,
                request,
                longlived_allocator,
            );
        } else {
            _ = socket.send(method_not_allowed_response) catch |send_error| {
                log.err(
                    "{} <== Method not allowed send error: {}",
                    .{ remote_endpoint, send_error },
                );
            };

            log.info(
                "{} <== 405 Method Not Allowed: {}",
                .{ remote_endpoint, request.request_line.method },
            );

            socket_set.remove(socket);
            socket.close();
            arena.deinit();
            longlived_allocator.destroy(arena);

            return Connection.idle;
        }
    }

    return connection.*;
}

fn removeFaultedReceivingSocket(receiving: ReceivingState, socket_set: *SocketSet) bool {
    if (socket_set.isFaulted(receiving.socket)) {
        socket_set.remove(receiving.socket);
        receiving.socket.close();

        return true;
    }

    return false;
}

fn removeFaultedSendingSocket(sending: *SendingState, socket_set: *SocketSet) bool {
    if (socket_set.isFaulted(sending.socket)) {
        sending.deinit(socket_set);

        return true;
    }

    return false;
}

const receiving_state_timeout = 30_000_000_000;

const not_found_response =
    \\HTTP/1.1 404 Not found
    \\Content-length: 14
    \\
    \\File not found
;

const not_modified_response =
    \\HTTP/1.1 304 Not modified
    \\
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

fn temporaryRedirect(allocator: *mem.Allocator, location: []const u8) ![]const u8 {
    const response_format =
        \\HTTP/1.1 307 Temporary Redirect
        \\Location: {}
        \\
        \\
    ;

    return try fmt.allocPrint(allocator, response_format, .{location});
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

fn removeLeadingSlashes(string: []const u8) []const u8 {
    return mem.trimLeft(u8, string, "/");
}

fn isDirectory(directory: fs.Dir, path: []const u8) bool {
    var resource_as_directory: ?fs.Dir = directory.openDir(
        path,
        .{},
    ) catch |err| null;
    if (resource_as_directory) |*d| {
        d.close();

        return true;
    } else {
        return false;
    }
}
