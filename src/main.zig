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
const BlockList = @import("./blocklist.zig").BlockList;
const Connection = @import("./connection.zig").Connection;
const ReceivingState = @import("./connection.zig").ReceivingState;
const SendingState = @import("./connection.zig").SendingState;
const handleConnection = @import("./connection.zig").handleConnection;

const debug_prints = false;

pub const log_level = .info;

const Options = struct {
    port: u16,
    chunk_size: u16 = 256,
    static_root: []const u8 = "./static/",
    uid: ?u32 = null,
    blocklist: ?BlockList = null,
    memory_debug: bool = false,
};

pub fn main() anyerror!void {
    try network.init();
    defer network.deinit();

    const options = try getCommandLineOptions();

    const shutdown_key = try getShutDownKey();
    log.info("Shutdown key is: {}", .{shutdown_key});

    const endpoint = network.EndPoint{
        .address = network.Address{ .ipv4 = .{ .value = [_]u8{ 0, 0, 0, 0 } } },
        .port = options.port,
    };

    const socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.tcp);
    var connections = ArrayList(Connection).init(heap.page_allocator);
    try socket.bind(endpoint);
    try socket.listen();
    defer socket.close();
    if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
        try socket.enablePortReuse(true);
    }
    var socket_set = try SocketSet.init(heap.page_allocator);
    defer socket_set.deinit();
    try socket_set.add(socket, .{ .read = true, .write = true });

    var memory_buffer: [max_stack_file_read_size]u8 = undefined;
    var fixed_buffer_allocator = heap.FixedBufferAllocator.init(&memory_buffer);
    var request_stack_allocator = &fixed_buffer_allocator.allocator;
    var logging_allocator = heap.loggingAllocator(heap.page_allocator, std.io.getStdOut().writer());

    var running = true;
    const local_endpoint = try socket.getLocalEndPoint();

    if (options.uid) |uid| try setUid(uid);

    while (running) {
        _ = network.waitForSocketEvent(&socket_set, 10_000_000_000_000) catch |e| {
            if (builtin.os.tag == .windows) {
                switch (e) {
                    error.FileDescriptorNotASocket => {
                        debug.print("===== ERROR socket_set={}", .{socket_set});
                        for (connections.items) |connection, i| {
                            debug.print("===== ERROR connection{}={}", .{ i, connection });
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
                        log.err("Client aborted connection", .{});

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

            const remote_endpoint = client_socket.getRemoteEndPoint() catch |endpoint_error| {
                log.err("=== Unable to get client endpoint: {} ===", .{endpoint_error});

                switch (endpoint_error) {
                    error.UnsupportedAddressFamily,
                    error.Unexpected,
                    error.InsufficientBytes,
                    error.SystemResources,
                    => {
                        client_socket.close();

                        continue;
                    },
                    error.NotConnected => continue,
                }
            };
            if (options.blocklist == null or !options.blocklist.?.isBlocked(
                remote_endpoint.address.ipv4,
            )) {
                socket_set.add(
                    client_socket,
                    .{ .read = true, .write = true },
                ) catch |socket_add_error| {
                    switch (socket_add_error) {
                        error.OutOfMemory => {
                            log.err(
                                "=== OOM when trying to add socket in socket_set: {} ===",
                                .{remote_endpoint},
                            );

                            client_socket.close();

                            continue;
                        },
                    }
                };
                insertIntoFirstFree(
                    &connections,
                    client_socket,
                    remote_endpoint,
                ) catch |insert_connection_error| {
                    switch (insert_connection_error) {
                        error.OutOfMemory => {
                            log.err(
                                "=== OOM when trying to add connection: {} ===",
                                .{remote_endpoint},
                            );
                            client_socket.close();

                            continue;
                        },
                    }
                };
            } else {
                client_socket.close();
                log.info("Blocked connection from: {}", .{remote_endpoint});
            }
        }

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
                if (options.memory_debug) &logging_allocator.allocator else heap.page_allocator,
                local_endpoint,
                &socket_set,
                options.chunk_size,
                options.memory_debug,
                connections,
                options.static_root,
                shutdown_key,
                &running,
            );
            fixed_buffer_allocator.reset();
        }
    }

    for (connections.items) |*connection| {
        switch (connection.*) {
            .idle => {},
            .receiving => |receiving| {
                receiving.socket.close();
            },
            .sending => |*sending| {
                sending.socket.close();
                sending.deinit(&socket_set);
            },
        }
    }
}

fn setUid(id: u32) !void {
    if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
        try std.os.setuid(id);
    }
}

fn getCommandLineOptions() !Options {
    const arguments = try process.argsAlloc(heap.page_allocator);
    const process_name = arguments[0];
    const usage = "Usage: {} <port> [chunk_size=256] [static_root=./static] [blocklist=null] [uid=null] [memory-debug=false]";
    if (arguments.len < 2) {
        log.err(usage, .{process_name});

        process.exit(1);
    }

    const port = try fmt.parseInt(u16, arguments[1], 10);
    var options = Options{ .port = port };

    for (arguments) |argument| {
        if (mem.startsWith(u8, argument, "memory-debug")) {
            var it = mem.split(argument, "=");
            _ = it.next();
            if (it.next()) |memory_debug| {
                options.memory_debug = if (mem.eql(u8, memory_debug, "true")) true else false;
            }
        } else if (mem.startsWith(u8, argument, "uid=")) {
            var it = mem.split(argument, "=");
            _ = it.next();
            if (it.next()) |uid_value| {
                options.uid = try fmt.parseUnsigned(u16, uid_value, 10);
            }
        } else if (mem.startsWith(u8, argument, "blocklist")) {
            var it = mem.split(argument, "=");
            _ = it.next();
            if (it.next()) |filename| {
                const blockListSlice = try fs.cwd().readFileAlloc(
                    heap.page_allocator,
                    filename,
                    1_000_000,
                );

                options.blocklist = try BlockList.fromSlice(heap.page_allocator, blockListSlice);
            }
        } else if (mem.startsWith(u8, argument, "chunk-size")) {
            var it = mem.split(argument, "=");
            _ = it.next();
            if (it.next()) |chunk_size| {
                options.chunk_size = try fmt.parseUnsigned(u16, chunk_size, 10);
            }
        } else if (mem.startsWith(u8, argument, "static-root")) {
            var it = mem.split(argument, "=");
            _ = it.next();
            if (it.next()) |static_root_argument| {
                const static_root = if (!mem.endsWith(u8, static_root_argument, "/"))
                    try mem.concat(
                        heap.page_allocator,
                        u8,
                        &[_][]const u8{ static_root_argument, "/" },
                    )
                else
                    try heap.page_allocator.dupe(u8, static_root_argument);

                options.static_root = static_root;
            }
        }
    }

    process.argsFree(heap.page_allocator, arguments);

    return options;
}

fn insertIntoFirstFree(
    connections: *ArrayList(Connection),
    socket: Socket,
    endpoint: EndPoint,
) !void {
    const timestamp = std.time.nanoTimestamp();
    var found_slot = false;
    const receiving_connection = Connection.receiving(socket, endpoint);

    for (connections.items) |*connection, i| {
        switch (connection.*) {
            .idle => {
                connection.* = receiving_connection;
                found_slot = true;

                break;
            },
            .receiving, .sending => {},
        }
    }

    if (!found_slot) try connections.append(receiving_connection);
}

fn getShutDownKey() !u128 {
    var random_bytes: [8]u8 = undefined;
    try std.crypto.randomBytes(random_bytes[0..]);
    const seed = mem.readIntLittle(u64, random_bytes[0..8]);
    var r = std.rand.DefaultCsprng.init(seed);

    return r.random.int(u128);
}

const max_stack_file_read_size = 4_000_000;
const max_heap_file_read_size = 1_000_000_000_000;
