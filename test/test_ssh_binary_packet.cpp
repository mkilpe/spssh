
#include "log.hpp"
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/ssh_binary_packet.hpp"
#include "ssh/core/ssh_config.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

std::string to_hex(securepath::ssh::const_span span) {
	char const values[] = "0123456789ABCDEF";
	std::string s;
	for(auto&& e : span) {
		s += values[std::to_integer<std::uint8_t>(e) >> 4];
		s += values[std::to_integer<std::uint8_t>(e) & 0x0F];
	}
	return s;
}


namespace securepath::ssh::test {

ssh_config test_configs[] =
	{
		{}
		,{.use_in_place_buffer = false}
		,{.random_packet_padding = false}
		,{.max_out_buffer_size = 1024, .use_in_place_buffer = false}
		,{.shrink_out_buffer_size = 0, .use_in_place_buffer = false}
	};

TEST_CASE("ssh_binary_packet", "[unit]") {
	auto config_i = GENERATE(range(0, int(sizeof(test_configs)/sizeof(ssh_config))), 1);

	ssh_config config = test_configs[config_i];
	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, test_log());
	REQUIRE(send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));
	CHECK(buf.used_size() > 0);

	ssh_binary_packet bp_2(config, test_log());
	REQUIRE(bp_2.try_decode_header(buf.get()));
	auto span = bp_2.decrypt_packet(buf.get(), temp_buf);
	REQUIRE(!span.empty());

	ser::disconnect::load packet(ser::match_type_t, span);
	REQUIRE(packet);

	auto & [code, desc, ignore] = packet;
	CHECK(code == 1);
	CHECK(desc == "test 1");
	CHECK(ignore == "test 2");
}

TEST_CASE("ssh_binary_packet retry sending", "[unit]") {

	ssh_config config{.use_in_place_buffer = false};
	string_out_buffer out_too_small{10};
	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, test_log());
	REQUIRE(!send_packet<ser::disconnect>(bp_1, out_too_small, 1, "test 1", "test 2"));
	CHECK(bp_1.error() == ssh_noerror);
	REQUIRE(!bp_1.retry_send(out_too_small));
	REQUIRE(bp_1.retry_send(buf));

	ssh_binary_packet bp_2(config, test_log());
	REQUIRE(bp_2.try_decode_header(buf.get()));
	auto span = bp_2.decrypt_packet(buf.get(), temp_buf);
	CHECK(bp_1.error() == ssh_noerror);
	REQUIRE(!span.empty());

	ser::disconnect::load packet(ser::match_type_t, span);
	REQUIRE(packet);

	auto & [code, desc, ignore] = packet;
	CHECK(code == 1);
	CHECK(desc == "test 1");
	CHECK(ignore == "test 2");
}

TEST_CASE("ssh_binary_packet failing", "[unit]") {
	ssh_config config;
	config.max_out_buffer_size = 25;
	config.use_in_place_buffer = false;

	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, test_log());
	CHECK(!send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));
	CHECK(bp_1.error() == spssh_memory_error);
}
}