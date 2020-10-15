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
const io = std.io;

const network = @import("network");

const parsing = @import("./parsing.zig");

const connection = @import("./connection.zig");
const ArrayList = std.ArrayList;
const Socket = network.Socket;
const SocketSet = network.SocketSet;
const EndPoint = network.EndPoint;
const BlockList = @import("./blocklist.zig").BlockList;
const Connection = connection.Connection;
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
    dynamic_cache_size: u64 = 0,
};

pub fn Server(comptime handle_connection: anytype) type {
    return struct {
        const Self = @This();

        endpoint: network.EndPoint,
        socket: Socket,
        connections: ArrayList(Connection),
        socket_set: SocketSet,
        request_stack_allocator: *mem.Allocator,
        fixed_buffer_allocator: *heap.FixedBufferAllocator,
        long_lived_allocator: *mem.Allocator,
        chunk_size: u16,
        memory_debug: bool,
        running: bool,
        local_endpoint: network.EndPoint,
        options: Options,

        pub fn init(
            fixed_buffer_allocator: *heap.FixedBufferAllocator,
            infrastructure_allocator: *mem.Allocator,
            long_lived_allocator: *mem.Allocator,
            address: network.Address,
            port: u16,
            chunk_size: u16,
            memory_debug: bool,
            options: Options,
        ) !Self {
            var request_stack_allocator = &fixed_buffer_allocator.allocator;

            const endpoint = network.EndPoint{
                .address = address,
                .port = port,
            };
            const socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.tcp);
            var connections = ArrayList(Connection).init(infrastructure_allocator);
            try socket.bind(endpoint);
            try socket.listen();
            if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
                try socket.enablePortReuse(true);
            }
            var socket_set = try SocketSet.init(infrastructure_allocator);

            try socket_set.add(socket, .{ .read = true, .write = true });

            const local_endpoint = try socket.getLocalEndPoint();

            return Self{
                .endpoint = endpoint,
                .socket = socket,
                .socket_set = socket_set,
                .request_stack_allocator = request_stack_allocator,
                .fixed_buffer_allocator = fixed_buffer_allocator,
                .long_lived_allocator = long_lived_allocator,
                .chunk_size = chunk_size,
                .memory_debug = memory_debug,
                .connections = connections,
                .running = false,
                .local_endpoint = local_endpoint,
                .options = options,
            };
        }

        pub fn deinit(self: Self) void {
            self.socket.close();
            self.socket_set.deinit();
        }

        pub fn run(self: *Self) !void {
            self.running = true;

            while (self.running) {
                _ = network.waitForSocketEvent(&self.socket_set, 10_000_000_000_000) catch |e| {
                    if (builtin.os.tag == .windows) {
                        switch (e) {
                            error.FileDescriptorNotASocket => {
                                debug.print("===== ERROR socket_set={}", .{self.socket_set});
                                for (self.connections.items) |c, i| {
                                    debug.print("===== ERROR connection{}={}", .{ i, c });
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

                if (self.socket_set.isReadyRead(self.socket)) {
                    const client_socket = self.socket.accept() catch |e| {
                        switch (e) {
                            error.SocketNotListening => {
                                log.err("Socket not listening", .{});

                                continue;
                            },
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
                    if (self.options.blocklist == null or
                        !self.options.blocklist.?.isBlocked(remote_endpoint.address.ipv4))
                    {
                        self.socket_set.add(
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
                            &self.connections,
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

                for (self.connections.items) |*c| {
                    c.* = try handle_connection(
                        c,
                        self.request_stack_allocator,
                        self.long_lived_allocator,
                        self.local_endpoint,
                        &self.socket_set,
                        self.options.chunk_size,
                        self.options.memory_debug,
                        self.connections,
                        self.options.static_root,
                        &self.running,
                    );

                    self.fixed_buffer_allocator.reset();
                }
            }

            for (self.connections.items) |*c| {
                switch (c.*) {
                    .idle => {},
                    .receiving => |receiving| {
                        receiving.socket.close();
                    },
                    .sending => |*sending| {
                        sending.socket.close();
                        sending.deinit(&self.socket_set);
                    },
                }
            }
        }
    };
}

const GeneralPurposeAllocator = heap.GeneralPurposeAllocator(.{});

pub fn main() anyerror!void {
    try network.init();
    defer network.deinit();

    const options = try getCommandLineOptions(heap.page_allocator);

    var logging_allocator = heap.loggingAllocator(heap.page_allocator, io.getStdOut().writer());
    var general_purpose_allocator = GeneralPurposeAllocator{};

    const long_lived_allocator = if (options.memory_debug)
        &logging_allocator.allocator
    else
        &general_purpose_allocator.allocator;

    var memory_buffer: [max_stack_file_read_size]u8 = undefined;
    var fixed_buffer_allocator = heap.FixedBufferAllocator.init(&memory_buffer);

    var server = try Server(handleConnection).init(
        &fixed_buffer_allocator,
        heap.page_allocator,
        long_lived_allocator,
        network.Address{ .ipv4 = .{ .value = [_]u8{ 0, 0, 0, 0 } } },
        options.port,
        options.chunk_size,
        options.memory_debug,
        options,
    );
    if (options.uid) |uid| try setUid(uid);

    try server.run();
}

fn setUid(id: u32) !void {
    if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
        try std.os.setuid(id);
    }
}

fn getCommandLineOptions(allocator: *mem.Allocator) !Options {
    const arguments = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, arguments);

    const process_name = arguments[0];
    const usage = "Usage: {} <port> [chunk-size=256] [static-root=./static] [blocklist=null]" ++
        " [uid=null] [memory-debug=false] [dynamic-cache-size=0]";
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
                options.memory_debug = mem.eql(u8, memory_debug, "true");
            }
        } else if (mem.startsWith(u8, argument, "dynamic-cache-size=")) {
            var it = mem.split(argument, "=");
            _ = it.next();
            if (it.next()) |dynamic_cache_size_string| {
                options.dynamic_cache_size = try fmt.parseUnsigned(
                    u64,
                    dynamic_cache_size_string,
                    10,
                );
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
                    allocator,
                    filename,
                    1_000_000,
                );

                options.blocklist = try BlockList.fromSlice(allocator, blockListSlice);
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
                        allocator,
                        u8,
                        &[_][]const u8{ static_root_argument, "/" },
                    )
                else
                    try allocator.dupe(u8, static_root_argument);

                options.static_root = static_root;
            }
        }
    }

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

    for (connections.items) |*c, i| {
        switch (c.*) {
            .idle => {
                c.* = receiving_connection;
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
