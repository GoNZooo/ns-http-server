const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const meta = std.meta;

const ArrayList = std.ArrayList;

pub const Request = struct {
    const Self = @This();

    request_line: RequestLine,
    headers: ArrayList(Header),
    body: []const u8,
    request_text: []const u8,
    allocator: *mem.Allocator,

    /// The caller is responsible for calling `result.deinit()`, which frees all the allocated
    /// structures.
    pub fn fromSlice(allocator: *mem.Allocator, slice: []const u8) !Self {
        var request_text = try allocator.dupe(u8, slice);
        errdefer allocator.free(request_text);
        var it = mem.split(request_text, "\n");
        const request_line_slice = it.next() orelse unreachable;
        const request_line = try RequestLine.fromSlice(allocator, request_line_slice);
        var header_list = ArrayList(Header).init(allocator);
        errdefer header_list.deinit();
        var line = it.next();
        while (line != null and !mem.eql(u8, line.?, "\r")) : (line = it.next()) {
            try header_list.append(try Header.fromSlice(line.?));
        }
        const body = it.rest();

        return Self{
            .request_line = request_line,
            .headers = header_list,
            .body = body,
            .allocator = allocator,
            .request_text = request_text,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.body);
        self.headers.deinit();
        self.allocator.free(request_text);
    }
};

pub const RequestLine = struct {
    const Self = @This();

    method: Method,
    resource: []const u8,
    version: Version,

    pub fn fromSlice(allocator: *mem.Allocator, slice: []const u8) !Self {
        var it = mem.split(mem.trimRight(u8, slice, "\r\n"), " ");

        const maybe_method_slice = it.next();
        if (maybe_method_slice == null) return error.NoMethodGiven;
        const method = try Method.fromSlice(maybe_method_slice.?);

        const maybe_resource_slice = it.next();
        if (maybe_resource_slice == null) return error.NoResourceGiven;
        const resource_slice = maybe_resource_slice.?;
        const resource = try allocator.dupe(u8, resource_slice);

        const maybe_version_slice = it.next();
        if (maybe_version_slice == null) return error.NoVersionGiven;
        const version = try Version.fromSlice(maybe_version_slice.?);

        return Self{
            .method = method,
            .resource = resource,
            .version = version,
        };
    }
};

pub const Header = union(enum) {
    const Self = @This();

    accept_encoding: []const u8,
    access_control_allow_credentials: bool,
    access_control_allow_headers: []const u8,
    access_control_allow_methods: []const u8,
    access_control_allow_origin: []const u8,
    access_control_max_age: u64,
    access_control_request_method: Method,
    cache_control: CacheControl,
    connection: ConnectionStatus,
    content_size: usize,
    cookie: []const u8,
    cross_origin_resource_policy: CrossOriginResourcePolicy,
    device_memory: f32,
    early_data: u32,
    etag: ETag,
    host: []const u8,
    origin: ?Origin,
    referrer: []const u8,
    upgrade_insecure_requests: u32,
    user_agent: []const u8,
    if_none_match: []const u8,
    // I want to have something better here, ideally a slice of slices but I can't very well
    // construct an array and return a slice to it in the parsing as it'll go out of scope.
    // I need to come up with something neat here.
    x_forwarded_for: []const u8,

    unknown: void,

    pub fn fromSlice(slice: []const u8) !Header {
        var maybe_colon_index = mem.indexOf(u8, slice, ":");
        if (maybe_colon_index) |colon_index| {
            var name_buffer: [2048]u8 = undefined;
            var header_name = name_buffer[0..colon_index];
            _ = lowerCase(slice[0..colon_index], header_name);
            const header_value = mem.trim(u8, slice[(colon_index + 1)..], " \r\n");
            if (mem.eql(u8, header_name, "content-size")) {
                const content_size = try fmt.parseUnsigned(usize, header_value, 10);

                return Header{ .content_size = content_size };
            } else if (mem.eql(u8, header_name, "accept-encoding")) {
                const encodings = header_value;

                return Header{ .accept_encoding = encodings };
            } else if (mem.eql(u8, header_name, "connection")) {
                const connection_status = try ConnectionStatus.fromSlice(header_value);

                return Header{ .connection = connection_status };
            } else if (mem.eql(u8, header_name, "host")) {
                const host = header_value;

                return Header{ .host = host };
            } else if (mem.eql(u8, header_name, "user-agent")) {
                const user_agent = header_value;

                return Header{ .user_agent = user_agent };
            } else if (mem.eql(u8, header_name, "cache-control")) {
                const cache_control = try CacheControl.fromSlice(header_value);

                return Header{ .cache_control = cache_control };
            } else if (mem.eql(u8, header_name, "etag")) {
                const etag = try ETag.fromSlice(header_value);

                return Header{ .etag = etag };
            } else if (mem.eql(u8, header_name, "if-none-match")) {
                const if_none_match = header_value;

                return Header{ .if_none_match = if_none_match };
            } else if (mem.eql(u8, header_name, "referer")) {
                const referrer = header_value;

                return Header{ .referrer = referrer };
            } else if (mem.eql(u8, header_name, "x-forwarded-for")) {
                const forwards = header_value;

                return Header{ .x_forwarded_for = forwards };
            } else if (mem.eql(u8, header_name, "access-control-max-age")) {
                const max_age = try fmt.parseUnsigned(u64, header_value, 10);

                return Header{ .access_control_max_age = max_age };
            } else if (mem.eql(u8, header_name, "device-memory")) {
                const memory = try fmt.parseFloat(f32, header_value);

                return Header{ .device_memory = memory };
            } else if (mem.eql(u8, header_name, "cross-origin-resource-policy")) {
                const resource_policy = try CrossOriginResourcePolicy.fromSlice(header_value);

                return Header{ .cross_origin_resource_policy = resource_policy };
            } else if (mem.eql(u8, header_name, "access-control-allow-headers")) {
                const allowed_headers = header_value;

                return Header{ .access_control_allow_headers = allowed_headers };
            } else if (mem.eql(u8, header_name, "access-control-request-method")) {
                const method = try Method.fromSlice(header_value);

                return Header{ .access_control_request_method = method };
            } else if (mem.eql(u8, header_name, "access-control-allow-methods")) {
                const methods = header_value;

                return Header{ .access_control_allow_methods = methods };
            } else if (mem.eql(u8, header_name, "access-control-allow-origin")) {
                const origin = header_value;

                return Header{ .access_control_allow_origin = origin };
            } else if (mem.eql(u8, header_name, "cookie")) {
                const cookie_string = header_value;

                return Header{ .cookie = cookie_string };
            } else if (mem.eql(u8, header_name, "upgrade-insecure-requests")) {
                const requests = try fmt.parseUnsigned(u32, header_value, 10);

                return Header{ .upgrade_insecure_requests = requests };
            } else if (mem.eql(u8, header_name, "access-control-allow-credentials")) {
                const allow = if (mem.eql(u8, header_value, "true"))
                    true
                else if (mem.eql(u8, header_value, "false"))
                    false
                else
                    return error.UnableToParseAllowCredentials;

                return Header{ .access_control_allow_credentials = allow };
            } else if (mem.eql(u8, header_name, "early-data")) {
                const early = try fmt.parseUnsigned(u32, header_value, 10);

                return Header{ .early_data = early };
            } else if (mem.eql(u8, header_name, "origin")) {
                const origin = try Origin.fromSlice(header_value);

                return Header{ .origin = origin };
            } else {
                return Header.unknown;
            }
        } else {
            return error.UnableToFindHeaderSeparator;
        }
    }
};

pub const CustomHeader = struct {
    name: []const u8,
    value: []const u8,
};

pub const ETag = union(enum) {
    normal: []const u8,
    weak: []const u8,

    pub fn fromSlice(slice: []const u8) !ETag {
        var it = mem.split(slice, "\"");
        if (it.next()) |part1| {
            if (mem.eql(u8, part1, "W/")) {
                if (it.next()) |etag| {
                    return ETag{ .weak = etag };
                } else {
                    return error.UnableToParseWeakETagValue;
                }
            } else {
                if (it.next()) |etag| {
                    return ETag{ .normal = etag };
                } else {
                    return error.UnableToParseNormalETagValue;
                }
            }
        }

        return error.UnableToParseETag;
    }
};

pub const CrossOriginResourcePolicy = enum {
    same_site,
    same_origin,
    cross_origin,

    pub fn fromSlice(slice: []const u8) !CrossOriginResourcePolicy {
        if (mem.eql(u8, slice, "same-site")) {
            return .same_site;
        } else if (mem.eql(u8, slice, "same-origin")) {
            return .same_origin;
        } else if (mem.eql(u8, slice, "cross-origin")) {
            return .cross_origin;
        } else {
            return error.UnableToParseCrossOriginResourcePolicy;
        }
    }
};

pub const CacheControl = union(enum) {
    no_cache: void,
    no_store: void,
    no_transform: void,
    only_if_cached: void,
    max_age: u64,
    max_stale: ?u64,
    min_fresh: u64,

    pub fn fromSlice(slice: []const u8) !CacheControl {
        if (mem.eql(u8, slice, "no-cache")) {
            return .no_cache;
        } else if (mem.eql(u8, slice, "no-store")) {
            return .no_store;
        } else if (mem.eql(u8, slice, "no-transform")) {
            return .no_transform;
        } else if (mem.eql(u8, slice, "only-if-cached")) {
            return .only_if_cached;
        } else {
            if (mem.indexOf(u8, slice, "=")) |equal_index| {
                // check for things here that require equal
                const control_type = slice[0..equal_index];
                if (mem.eql(u8, control_type, "max-age")) {
                    const trimmed = mem.trim(u8, slice[(equal_index + 1)..], " ");
                    const value = try fmt.parseUnsigned(u64, trimmed, 10);

                    return CacheControl{ .max_age = value };
                } else if (mem.eql(u8, control_type, "min-fresh")) {
                    const trimmed = mem.trim(u8, slice[(equal_index + 1)..], " ");
                    const value = try fmt.parseUnsigned(u64, trimmed, 10);

                    return CacheControl{ .min_fresh = value };
                } else if (mem.eql(u8, control_type, "max-stale")) {
                    const trimmed = mem.trim(u8, slice[(equal_index + 1)..], " ");
                    const value = try fmt.parseUnsigned(u64, trimmed, 10);

                    return CacheControl{ .max_stale = value };
                }
            } else if (mem.eql(u8, slice, "max-stale")) {
                return CacheControl{ .max_stale = null };
            } else {
                return error.UnableToParseCacheControlValue;
            }
        }

        return error.UnableToParseCacheControlHeader;
    }
};

pub const Encoding = enum(u8) {
    gzip,
    compress,
    deflate,
    brotli,
    identity,
    anything,

    pub fn fromSlice(slice: []const u8) !Encoding {
        if (mem.eql(u8, slice, "gzip")) {
            return .gzip;
        } else if (mem.eql(u8, slice, "compress")) {
            return .compress;
        } else if (mem.eql(u8, slice, "deflate")) {
            return .deflate;
        } else if (mem.eql(u8, slice, "br")) {
            return .brotli;
        } else if (mem.eql(u8, slice, "identity")) {
            return .identity;
        } else if (mem.eql(u8, slice, "*")) {
            return .anything;
        } else {
            return error.UnableToParseDecoding;
        }
    }
};

pub const Origin = struct {
    scheme: Scheme,
    hostname: []const u8,
    port: ?u16,

    pub fn fromSlice(slice: []const u8) !?Origin {
        if (mem.eql(u8, slice, "null")) {
            return null;
        } else if (mem.indexOf(u8, slice, "://")) |scheme_delimiter_index| {
            const scheme = try Scheme.fromSlice(slice[0..scheme_delimiter_index]);
            const rest = slice[(scheme_delimiter_index + 3)..];
            if (mem.indexOf(u8, rest, ":")) |port_index| {
                const hostname = rest[0..port_index];
                const port = try fmt.parseUnsigned(u16, rest[(port_index + 1)..], 10);

                return Origin{ .scheme = scheme, .hostname = hostname, .port = port };
            } else {
                const port = null;
                const hostname = rest[0..];

                return Origin{ .scheme = scheme, .hostname = hostname, .port = port };
            }
        } else {
            return error.UnableToParseOriginScheme;
        }
    }
};

pub const Scheme = enum(u8) {
    https,
    http,

    pub fn fromSlice(slice: []const u8) !Scheme {
        if (mem.eql(u8, slice, "https")) {
            return .https;
        } else if (mem.eql(u8, slice, "http")) {
            return .http;
        } else {
            return error.UnableToParseScheme;
        }
    }
};

pub const ConnectionStatus = enum(u8) {
    close,
    keep_alive,

    pub fn fromSlice(slice: []const u8) !ConnectionStatus {
        if (mem.eql(u8, slice, "close")) {
            return .close;
        } else if (mem.eql(u8, slice, "keep-alive")) {
            return .keep_alive;
        } else {
            return error.UnableToParseConnectionStatus;
        }
    }
};

pub const Method = enum(u8) {
    get,
    head,
    put,
    post,
    delete,
    patch,
    options,
    connect,
    trace,

    pub fn fromSlice(slice: []const u8) !Method {
        if (mem.eql(u8, slice, "GET")) return .get;
        if (mem.eql(u8, slice, "HEAD")) return .head;
        if (mem.eql(u8, slice, "PUT")) return .put;
        if (mem.eql(u8, slice, "POST")) return .post;
        if (mem.eql(u8, slice, "DELETE")) return .delete;
        if (mem.eql(u8, slice, "PATCH")) return .patch;
        if (mem.eql(u8, slice, "OPTIONS")) return .options;
        if (mem.eql(u8, slice, "CONNECT")) return .connect;
        if (mem.eql(u8, slice, "TRACE")) return .trace;

        return error.UnableToParseMethod;
    }

    pub fn toSlice(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .head => "HEAD",
            .put => "PUT",
            .post => "POST",
            .delete => "DELETE",
            .patch => "PATCH",
            .options => "OPTIONS",
            .connect => "CONNECT",
            .trace => "TRACE",
        };
    }
};

pub const Version = enum(u8) {
    http11,

    pub fn fromSlice(slice: []const u8) !Version {
        if (mem.eql(u8, slice[0..8], "HTTP/1.1")) return Version.http11;

        return error.UnableToParseVersion;
    }
};

test "parses basic request lines" {
    const request_line_string1 = "GET /sub-path/interesting_document.html HTTP/1.1\r\n";
    const request_line1 = try RequestLine.fromSlice(request_line_string1[0..]);
    testing.expectEqual(request_line1.method, .get);
    testing.expectEqualStrings(request_line1.resourceSlice(), "/sub-path/interesting_document.html");
    testing.expectEqual(request_line1.version, .http11);

    const request_line_string2 = "POST /interesting_document HTTP/1.1\r\n";
    const request_line2 = try RequestLine.fromSlice(request_line_string2[0..]);
    testing.expectEqual(request_line2.method, .post);
    testing.expectEqualStrings(request_line2.resourceSlice(), "/interesting_document");
    testing.expectEqual(request_line2.version, .http11);

    const request_line_string3 = "HEAD /interesting_document HTTP/1.1\r\n";
    const request_line3 = try RequestLine.fromSlice(request_line_string3[0..]);
    testing.expectEqual(request_line3.method, .head);
    testing.expectEqualStrings(request_line3.resourceSlice(), "/interesting_document");
    testing.expectEqual(request_line3.version, .http11);

    const request_line_string4 = "PUT / HTTP/1.1\r\n";
    const request_line4 = try RequestLine.fromSlice(request_line_string4[0..]);
    testing.expectEqual(request_line4.method, .put);
    testing.expectEqualStrings(request_line4.resourceSlice(), "/");
    testing.expectEqual(request_line4.version, .http11);

    const request_line_string5 = "PATCH / HTTP/1.1\r\n";
    const request_line5 = try RequestLine.fromSlice(request_line_string5[0..]);
    testing.expectEqual(request_line5.method, .patch);
    testing.expectEqualStrings(request_line5.resourceSlice(), "/");
    testing.expectEqual(request_line5.version, .http11);

    const request_line_string6 = "OPTIONS / HTTP/1.1\r\n";
    const request_line6 = try RequestLine.fromSlice(request_line_string6[0..]);
    testing.expectEqual(request_line6.method, .options);
    testing.expectEqualStrings(request_line6.resourceSlice(), "/");
    testing.expectEqual(request_line6.version, .http11);

    const request_line_string7 = "DELETE / HTTP/1.1\r\n";
    const request_line7 = try RequestLine.fromSlice(request_line_string7[0..]);
    testing.expectEqual(request_line7.method, .delete);
    testing.expectEqualStrings(request_line7.resourceSlice(), "/");
    testing.expectEqual(request_line7.version, .http11);

    const request_line_string8 = "CONNECT / HTTP/1.1\r\n";
    const request_line8 = try RequestLine.fromSlice(request_line_string8[0..]);
    testing.expectEqual(request_line8.method, .connect);
    testing.expectEqualStrings(request_line8.resourceSlice(), "/");
    testing.expectEqual(request_line8.version, .http11);

    const request_line_string9 = "TRACE / HTTP/1.1\r\n";
    const request_line9 = try RequestLine.fromSlice(request_line_string9[0..]);
    testing.expectEqual(request_line9.method, .trace);
    testing.expectEqualStrings(request_line9.resourceSlice(), "/");
    testing.expectEqual(request_line9.version, .http11);
}

test "parses basic headers" {
    const encodings = "gzip, deflate, br";
    const header_string1 = "Accept-Encoding: " ++ encodings ++ "\r\n";
    const header1 = try Header.fromSlice(header_string1);
    testing.expectEqual(meta.activeTag(header1), .accept_encoding);
    testing.expectEqualStrings(header1.accept_encoding, encodings);

    const header_string2 = "Content-Size: 1337\r\n";
    const header2 = try Header.fromSlice(header_string2);
    testing.expectEqual(meta.activeTag(header2), .content_size);
    testing.expectEqual(header2.content_size, 1337);

    const header_string3 = "Some-Custom-Header: Some-Custom-Value\r\n";
    const header3 = try Header.fromSlice(header_string3);
    testing.expectEqual(meta.activeTag(header3), .custom);
    testing.expectEqualStrings(header3.custom.name, "some-custom-header");
    testing.expectEqualStrings(header3.custom.value, "Some-Custom-Value");

    const header_string4 = "Content-Size: 42\r\n";
    const header4 = try Header.fromSlice(header_string4);
    testing.expectEqual(meta.activeTag(header4), .content_size);
    testing.expectEqual(header4.content_size, 42);

    const header_string5 = "Connection: keep-alive\r\n";
    const header5 = try Header.fromSlice(header_string5);
    testing.expectEqual(meta.activeTag(header5), .connection);
    testing.expectEqual(header5.connection, .keep_alive);

    const header_string6 = "Connection: close\r\n";
    const header6 = try Header.fromSlice(header_string6);
    testing.expectEqual(meta.activeTag(header6), .connection);
    testing.expectEqual(header6.connection, .close);

    const header_string7 = "Host: example-host.com\r\n";
    const header7 = try Header.fromSlice(header_string7);
    testing.expectEqual(meta.activeTag(header7), .host);
    testing.expectEqualStrings(header7.host, "example-host.com");

    const user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Gecko/20100101 Firefox/50.0";
    const header_string8 = "User-Agent: " ++ user_agent ++ "\r\n";
    const header8 = try Header.fromSlice(header_string8);
    testing.expectEqual(meta.activeTag(header8), .user_agent);
    testing.expectEqualStrings(header8.user_agent, user_agent);

    const header_string9 = "Cache-Control: max-age= 1337\r\n";
    const header9 = try Header.fromSlice(header_string9);
    testing.expectEqual(meta.activeTag(header9), .cache_control);
    testing.expectEqual(meta.activeTag(header9.cache_control), .max_age);
    testing.expectEqual(header9.cache_control.max_age, 1337);

    const header_string10 = "Cache-Control: min-fresh= 42 \r\n";
    const header10 = try Header.fromSlice(header_string10);
    testing.expectEqual(meta.activeTag(header10), .cache_control);
    testing.expectEqual(meta.activeTag(header10.cache_control), .min_fresh);
    testing.expectEqual(header10.cache_control.min_fresh, 42);

    const header_string11 = "Cache-Control: max-stale= 42 \r\n";
    const header11 = try Header.fromSlice(header_string11);
    testing.expectEqual(meta.activeTag(header11), .cache_control);
    testing.expectEqual(meta.activeTag(header11.cache_control), .max_stale);
    testing.expectEqual(header11.cache_control.max_stale, 42);

    const header_string12 = "Cache-Control: max-stale\r\n";
    const header12 = try Header.fromSlice(header_string12);
    testing.expectEqual(meta.activeTag(header12), .cache_control);
    testing.expectEqual(meta.activeTag(header12.cache_control), .max_stale);
    testing.expectEqual(header12.cache_control.max_stale, null);

    const header_string13 = "Cache-Control: no-cache\r\n";
    const header13 = try Header.fromSlice(header_string13);
    testing.expectEqual(meta.activeTag(header13), .cache_control);
    testing.expectEqual(meta.activeTag(header13.cache_control), .no_cache);

    const header_string14 = "Cache-Control: no-transform\r\n";
    const header14 = try Header.fromSlice(header_string14);
    testing.expectEqual(meta.activeTag(header14), .cache_control);
    testing.expectEqual(meta.activeTag(header14.cache_control), .no_transform);

    const header_string15 = "Cache-Control: only-if-cached\r\n";
    const header15 = try Header.fromSlice(header_string15);
    testing.expectEqual(meta.activeTag(header15), .cache_control);
    testing.expectEqual(meta.activeTag(header15.cache_control), .only_if_cached);

    const header_string16 = "Cache-Control: no-store\r\n";
    const header16 = try Header.fromSlice(header_string16);
    testing.expectEqual(meta.activeTag(header16), .cache_control);
    testing.expectEqual(meta.activeTag(header16.cache_control), .no_store);

    const header_string17 = "ETag: \"1234567890\"\r\n";
    const header17 = try Header.fromSlice(header_string17);
    testing.expectEqual(meta.activeTag(header17), .etag);
    testing.expectEqual(meta.activeTag(header17.etag), .normal);
    testing.expectEqualStrings(header17.etag.normal, "1234567890");

    const header_string18 = "ETag: W/\"1234567890\"\r\n";
    const header18 = try Header.fromSlice(header_string18);
    testing.expectEqual(meta.activeTag(header18), .etag);
    testing.expectEqual(meta.activeTag(header18.etag), .weak);
    testing.expectEqualStrings(header18.etag.weak, "1234567890");

    const header_string19 = "Referer: https://developer.mozilla.org/testpage.html\r\n";
    const header19 = try Header.fromSlice(header_string19);
    testing.expectEqual(meta.activeTag(header19), .referer);
    testing.expectEqualStrings(header19.referer, "https://developer.mozilla.org/testpage.html");

    const ips = "203.0.113.195, 70.41.3.18, 150.172.238.178";
    const header_string20 = "X-Forwarded-For: " ++ ips ++ "\r\n";
    const header20 = try Header.fromSlice(header_string20);
    testing.expectEqual(meta.activeTag(header20), .x_forwarded_for);
    testing.expectEqualStrings(header20.x_forwarded_for, ips);

    const header_string21 = "Access-Control-Max-Age: 42\r\n";
    const header21 = try Header.fromSlice(header_string21);
    testing.expectEqual(meta.activeTag(header21), .access_control_max_age);
    testing.expectEqual(header21.access_control_max_age, 42);

    const header_string22 = "Device-Memory: 0.25\r\n";
    const header22 = try Header.fromSlice(header_string22);
    testing.expectEqual(meta.activeTag(header22), .device_memory);
    testing.expectEqual(header22.device_memory, 0.25);

    const header_string23 = "Cross-Origin-Resource-Policy: same-site\r\n";
    const header23 = try Header.fromSlice(header_string23);
    testing.expectEqual(meta.activeTag(header23), .cross_origin_resource_policy);
    testing.expectEqual(header23.cross_origin_resource_policy, .same_site);

    const header_string24 = "Cross-Origin-Resource-Policy: same-origin\r\n";
    const header24 = try Header.fromSlice(header_string24);
    testing.expectEqual(meta.activeTag(header24), .cross_origin_resource_policy);
    testing.expectEqual(header24.cross_origin_resource_policy, .same_origin);

    const header_string25 = "Cross-Origin-Resource-Policy: cross-origin\r\n";
    const header25 = try Header.fromSlice(header_string25);
    testing.expectEqual(meta.activeTag(header25), .cross_origin_resource_policy);
    testing.expectEqual(header25.cross_origin_resource_policy, .cross_origin);

    const headers = "X-Custom-Header, Upgrade-Insecure-Requests";
    const header_string26 = "Access-Control-Allow-Headers: " ++ headers ++ "\r\n";
    const header26 = try Header.fromSlice(header_string26);
    testing.expectEqual(meta.activeTag(header26), .access_control_allow_headers);
    testing.expectEqualStrings(header26.access_control_allow_headers, headers);

    const header_string27 = "Access-Control-Request-Method: POST\r\n";
    const header27 = try Header.fromSlice(header_string27);
    testing.expectEqual(meta.activeTag(header27), .access_control_request_method);
    testing.expectEqual(header27.access_control_request_method, .post);

    const header_string28 = "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    const header28 = try Header.fromSlice(header_string28);
    testing.expectEqual(meta.activeTag(header28), .access_control_allow_methods);
    testing.expectEqualStrings(header28.access_control_allow_methods, "POST, GET, OPTIONS");

    const header_string29 = "Access-Control-Allow-Origin: https://developer.mozilla.org\r\n";
    const header29 = try Header.fromSlice(header_string29);
    testing.expectEqual(meta.activeTag(header29), .access_control_allow_origin);
    testing.expectEqualStrings(header29.access_control_allow_origin, "https://developer.mozilla.org");

    const cookies = "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1";
    const header_string30 = "Cookie: " ++ cookies ++ "\r\n";
    const header30 = try Header.fromSlice(header_string30);
    testing.expectEqual(meta.activeTag(header30), .cookie);
    testing.expectEqualStrings(header30.cookie, cookies);

    const header_string31 = "Upgrade-Insecure-Requests: 1\r\n";
    const header31 = try Header.fromSlice(header_string31);
    testing.expectEqual(meta.activeTag(header31), .upgrade_insecure_requests);
    testing.expectEqual(header31.upgrade_insecure_requests, 1);

    const header_string32 = "Access-Control-Allow-Credentials: true\r\n";
    const header32 = try Header.fromSlice(header_string32);
    testing.expectEqual(meta.activeTag(header32), .access_control_allow_credentials);
    testing.expectEqual(header32.access_control_allow_credentials, true);

    const header_string33 = "Access-Control-Allow-Credentials: false\r\n";
    const header33 = try Header.fromSlice(header_string33);
    testing.expectEqual(meta.activeTag(header33), .access_control_allow_credentials);
    testing.expectEqual(header33.access_control_allow_credentials, false);

    const header_string34 = "Early-Data: 1\r\n";
    const header34 = try Header.fromSlice(header_string34);
    testing.expectEqual(meta.activeTag(header34), .early_data);
    testing.expectEqual(header34.early_data, 1);

    const header_string35 = "Origin: https://somedomain.com:8080\r\n";
    const header35 = try Header.fromSlice(header_string35);
    testing.expectEqual(meta.activeTag(header35), .origin);
    testing.expectEqual(header35.origin.?.scheme, .https);
    testing.expectEqualStrings(header35.origin.?.hostname, "somedomain.com");
    testing.expectEqual(header35.origin.?.port, 8080);

    const header_string36 = "Origin: null\r\n";
    const header36 = try Header.fromSlice(header_string36);
    testing.expectEqual(meta.activeTag(header36), .origin);
    testing.expectEqual(header36.origin, null);
}

const MAX_RESOURCE_LENGTH = 2048;

fn lowerCase(slice: []const u8, buffer: []u8) []const u8 {
    for (slice) |c, i| {
        if (c >= 'A' and c <= 'Z') buffer[i] = c + 32 else buffer[i] = c;
    }

    return buffer[0..slice.len];
}
