const std = @import("std");

const mem = std.mem;
const log = std.log;
const page_allocator = std.heap.page_allocator;
const Signedness = std.builtin.Signedness;

const pcap = @cImport({
    @cInclude("pcap/pcap.h");
});

const MessageHeader = struct { version: u8 = 0x01, reserved: u8 = 0x00, protocol_id: u16 = 0x04_80, channel_id: u32 = 0x01_00_00_00 };

pub fn serialize(allocator: Allocator, comptime T: type, @"struct": T) ![]const u8 {
    const bit_size = @bitSizeOf(T);

    const @"type" = @Type(.{ .Int = .{ .bits = bit_size, .signedness = Signedness.unsigned } });

    var value: @"type" = 0;

    inline for (@typeInfo(T).Struct.fields) |field| {
        const field_value = @field(@"struct", field.name);
        value <<= @bitSizeOf(@TypeOf(field_value));
        value += field_value;
    }

    const value_big = mem.nativeToBig(@"type", value);

    const size = @sizeOf(T);
    const value_big_str = try allocator.alloc(u8, size);
    std.mem.copy(u8, value_big_str, @ptrCast(*const [size]u8, &value_big));

    return value_big_str;
}

pub fn inspect(in: []const u8) void {
    for (in) |char| {
        log.debug("{x}", .{char});
    }
}

pub fn main() !void {
    var arena = ArenaAllocator.init(page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const msg_hdr = MessageHeader{};
    const msg_hdr_str = try serialize(allocator, MessageHeader, msg_hdr);

    const error_buffer: [*c]const u8 = undefined;
    const pcap_handler = pcap.pcap_open_offline("/home/dan/pcap/sample_DEEP1.0.pcap", error_buffer);

    var packet_header: [*c]pcap.pcap_pkthdr = undefined;
    var packet_data: [*c]u8 = undefined;

    var i: usize = 0;
    while (pcap.pcap_next_ex(pcap_handler, &packet_header, &packet_data) == 1) : (i += 1) {
        var n = mem.indexOf(u8, packet_data[0 .. packet_header.*.caplen - 1], msg_hdr_str);

        if (n != null) {
            log.info("found {}", .{n.?});
        }

        if (i == 3) break;
    }
}
