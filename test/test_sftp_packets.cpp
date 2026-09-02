#include "log.hpp"
#include "util/sftp_fixtures.hpp"

#include "ssh/services/sftp/file_attributes.hpp"
#include "ssh/services/sftp/packet_ser_impl.hpp"
#include "ssh/services/sftp/protocol.hpp"
#include "ssh/services/sftp/sftp_common.hpp"

#include <external/catch/catch.hpp>

namespace securepath::ssh::test {
namespace {

using namespace securepath::ssh::sftp;

template<typename Packet, typename... Args>
void check_sftp_ser(std::uint8_t expected_type, Args&&... args) {
	byte_vector p;
	REQUIRE(ser::serialise_to_vector<Packet>(p, args...));
	REQUIRE(p.size() >= 5);
	// wire format: uint32 length, byte type
	CHECK(std::uint8_t(p[4]) == expected_type);

	typename Packet::load lp(ser::match_type_t, p);
	REQUIRE(lp);
	auto t = std::tuple<std::decay_t<Args>...>(args...);
	CHECK(t == [&]<std::size_t... I>(std::index_sequence<I...>) {
		return std::tuple<std::decay_t<Args>...>(lp.template get<I>()...);
	}(std::make_index_sequence<sizeof...(Args)>()));
}

struct framing_channel : sftp_common {
	framing_channel(transport_base& t, std::size_t in_buffer_size = default_sftp_in_buffer_size)
	: sftp_common(t, channel_side_info{1, 2*1024*1024, 32768}, default_buffer_size, in_buffer_size)
	{
	}

	void handle_sftp_packet(sftp_packet_type type, const_span data) override {
		received.push_back({type, byte_vector(data.begin(), data.end())});
	}

	std::vector<sftp_packet_data> received;
};

byte_vector make_raw_sftp_packet(std::uint8_t type, byte_vector const& payload) {
	byte_vector p;
	ssh_bf_writer w(p);
	w.write(std::uint32_t(payload.size() + 1));
	w.write(type);
	p.insert(p.end(), payload.begin(), payload.end());
	return p;
}

}

TEST_CASE("sftp protocol packet serialisation", "[unit][sftp]") {
	check_sftp_ser<init>(fxp_init, 3u);
	check_sftp_ser<version>(fxp_version, 3u);
	check_sftp_ser<open_request>(fxp_open, 1u, std::string_view("/some/file"), std::uint32_t(fxf_read|fxf_write));
	check_sftp_ser<close_request>(fxp_close, 2u, std::string_view("handle"));
	check_sftp_ser<read_request>(fxp_read, 3u, std::string_view("handle"), std::uint64_t(1234567890123), 32768u);
	check_sftp_ser<write_request>(fxp_write, 4u, std::string_view("handle"), std::uint64_t(42), std::string_view("data data"));
	check_sftp_ser<remove_request>(fxp_remove, 5u, std::string_view("/file"));
	check_sftp_ser<rename_request>(fxp_rename, 6u, std::string_view("/old"), std::string_view("/new"));
	check_sftp_ser<mkdir_request>(fxp_mkdir, 7u, std::string_view("/dir"));
	check_sftp_ser<rmdir_request>(fxp_rmdir, 8u, std::string_view("/dir"));
	check_sftp_ser<opendir_request>(fxp_opendir, 9u, std::string_view("/dir"));
	check_sftp_ser<readdir_request>(fxp_readdir, 10u, std::string_view("handle"));
	check_sftp_ser<stat_request>(fxp_stat, 11u, std::string_view("/file"));
	check_sftp_ser<lstat_request>(fxp_lstat, 12u, std::string_view("/file"));
	check_sftp_ser<fstat_request>(fxp_fstat, 13u, std::string_view("handle"));
	check_sftp_ser<setstat_request>(fxp_setstat, 14u, std::string_view("/file"));
	check_sftp_ser<fsetstat_request>(fxp_fsetstat, 15u, std::string_view("handle"));
	check_sftp_ser<readlink_request>(fxp_readlink, 16u, std::string_view("/link"));
	check_sftp_ser<symlink_request>(fxp_symlink, 17u, std::string_view("/link"), std::string_view("/target"));
	check_sftp_ser<realpath_request>(fxp_realpath, 18u, std::string_view("."));
	check_sftp_ser<extended_request>(fxp_extended, 19u, std::string_view("some@ext"));

	check_sftp_ser<status_response>(fxp_status, 20u, std::uint32_t(fx_eof), std::string_view("eof"), std::string_view(""));
	check_sftp_ser<handle_response>(fxp_handle, 21u, std::string_view("handle"));
	check_sftp_ser<data_response>(fxp_data, 22u, std::string_view("some data"));
	check_sftp_ser<name_response>(fxp_name, 23u, 2u);
	check_sftp_ser<attrs_response>(fxp_attrs, 24u);
	// this had a copy-paste bug earlier, make sure the type tag is right
	check_sftp_ser<extended_reply_response>(fxp_extended_reply, 25u);
}

TEST_CASE("sftp length patching", "[unit][sftp]") {
	byte_vector p;
	REQUIRE(ser::serialise_to_vector<attrs_response>(p, 1u));
	auto old_size = p.size();
	p.resize(old_size + 8); // simulate appending data
	patch_sftp_length(p);

	std::uint32_t length{};
	auto type = decode_sftp_type(p, length);
	CHECK(type == fxp_attrs);
	CHECK(length == p.size() - 4);
}

TEST_CASE("sftp file_attributes round trip", "[unit][sftp]") {
	file_attributes in;
	SECTION("empty") {
	}
	SECTION("size only") {
		in.size = 1234567890123ull;
	}
	SECTION("uid/gid") {
		in.uid = 1000;
		in.gid = 100;
	}
	SECTION("permissions") {
		in.permissions = 0100644;
	}
	SECTION("times") {
		in.atime = 1234567;
		in.mtime = 7654321;
	}
	SECTION("everything") {
		in.size = 42;
		in.uid = 1;
		in.gid = 2;
		in.permissions = 0100600;
		in.atime = 3;
		in.mtime = 4;
		in.extended.push_back(ext_data{"test@type", "value"});
		in.extended.push_back(ext_data{"other@type", "value2"});
	}

	byte_vector buf;
	ssh_bf_writer w(buf);
	REQUIRE(in.write(w));

	ssh_bf_reader r(buf);
	file_attributes out;
	REQUIRE(out.read(r));

	CHECK(in.size == out.size);
	CHECK(in.uid == out.uid);
	CHECK(in.gid == out.gid);
	CHECK(in.permissions == out.permissions);
	CHECK(in.atime == out.atime);
	CHECK(in.mtime == out.mtime);
	REQUIRE(in.extended.size() == out.extended.size());
	for(std::size_t i = 0; i != in.extended.size(); ++i) {
		CHECK(in.extended[i].type == out.extended[i].type);
		CHECK(in.extended[i].data == out.extended[i].data);
	}
}

TEST_CASE("sftp to_longname", "[unit][sftp]") {
	file_attributes a;
	a.size = 1234;
	a.uid = 1000;
	a.gid = 100;
	a.permissions = 0040755;
	a.mtime = 1234567890;

	auto ln = to_longname(a, "somedir");
	CHECK(ln.substr(0, 10) == "drwxr-xr-x");
	CHECK(ln.find("1234") != std::string::npos);
	CHECK(ln.find("somedir") != std::string::npos);

	a.permissions = 0100600;
	ln = to_longname(a, "file.txt");
	CHECK(ln.substr(0, 10) == "-rw-------");
}

TEST_CASE("sftp framing, multiple packets in one data block", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	framing_channel ch(transport);

	byte_vector stream;
	auto p1 = make_raw_sftp_packet(fxp_stat, byte_vector(10, std::byte{'a'}));
	auto p2 = make_raw_sftp_packet(fxp_lstat, byte_vector(20, std::byte{'b'}));
	auto p3 = make_raw_sftp_packet(fxp_open, byte_vector{});
	stream.insert(stream.end(), p1.begin(), p1.end());
	stream.insert(stream.end(), p2.begin(), p2.end());
	stream.insert(stream.end(), p3.begin(), p3.end());

	REQUIRE(ch.on_data(stream));

	REQUIRE(ch.received.size() == 3);
	CHECK(ch.received[0].type == fxp_stat);
	CHECK(ch.received[0].payload == byte_vector(10, std::byte{'a'}));
	CHECK(ch.received[1].type == fxp_lstat);
	CHECK(ch.received[1].payload == byte_vector(20, std::byte{'b'}));
	CHECK(ch.received[2].type == fxp_open);
	CHECK(ch.received[2].payload.empty());
}

TEST_CASE("sftp framing, packet split to pieces", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	framing_channel ch(transport);

	auto p1 = make_raw_sftp_packet(fxp_write, byte_vector(100, std::byte{'x'}));
	auto p2 = make_raw_sftp_packet(fxp_read, byte_vector(50, std::byte{'y'}));
	byte_vector stream;
	stream.insert(stream.end(), p1.begin(), p1.end());
	stream.insert(stream.end(), p2.begin(), p2.end());

	// split the stream at every possible position
	auto split = GENERATE(range(std::size_t{1}, std::size_t{160}));
	CAPTURE(split);

	REQUIRE(ch.on_data(safe_subspan(stream, 0, split)));
	REQUIRE(ch.on_data(safe_subspan(stream, split)));

	REQUIRE(ch.received.size() == 2);
	CHECK(ch.received[0].type == fxp_write);
	CHECK(ch.received[0].payload == byte_vector(100, std::byte{'x'}));
	CHECK(ch.received[1].type == fxp_read);
	CHECK(ch.received[1].payload == byte_vector(50, std::byte{'y'}));
}

TEST_CASE("sftp framing, byte at a time", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	framing_channel ch(transport);

	auto p1 = make_raw_sftp_packet(fxp_stat, byte_vector(33, std::byte{'z'}));
	for(std::size_t i = 0; i != p1.size(); ++i) {
		REQUIRE(ch.on_data(safe_subspan(p1, i, 1)));
	}

	REQUIRE(ch.received.size() == 1);
	CHECK(ch.received[0].type == fxp_stat);
	CHECK(ch.received[0].payload == byte_vector(33, std::byte{'z'}));
}

TEST_CASE("sftp framing, zero length packet disconnects", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	framing_channel ch(transport);

	byte_vector bad(5, std::byte{});
	CHECK(ch.on_data(bad));
	CHECK(transport.disconnected());
	CHECK(ch.received.empty());
}

TEST_CASE("sftp framing, too big packet disconnects", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	framing_channel ch(transport, 1024); // small in buffer

	byte_vector bad;
	ssh_bf_writer w(bad);
	w.write(std::uint32_t(2048)); // can never fit the buffer
	w.write(std::uint8_t(fxp_stat));
	CHECK(ch.on_data(bad));
	CHECK(transport.disconnected());
	CHECK(ch.received.empty());
}

TEST_CASE("sftp framing, buffer compaction", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	framing_channel ch(transport, 256); // in buffer fits only couple packets

	// feed lots of packets in pieces so that the buffer has to be compacted
	for(std::size_t i = 0; i != 50; ++i) {
		auto p = make_raw_sftp_packet(fxp_stat, byte_vector(100, std::byte(i)));
		REQUIRE(ch.on_data(safe_subspan(p, 0, 60)));
		REQUIRE(ch.on_data(safe_subspan(p, 60)));
	}

	REQUIRE(ch.received.size() == 50);
	for(std::size_t i = 0; i != 50; ++i) {
		CHECK(ch.received[i].payload == byte_vector(100, std::byte(i)));
	}
}

}
