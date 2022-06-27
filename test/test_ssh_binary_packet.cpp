
#include "crypto.hpp"
#include "log.hpp"
#include "random.hpp"
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/ssh_binary_packet.hpp"
#include "ssh/core/ssh_config.hpp"
#include "ssh/core/protocol.hpp"
#include <external/catch/catch.hpp>

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

template<typename Packet, typename... Args>
bool send_packet(ssh_binary_packet& bp, out_buffer& out, Args&&... args) {
	typename Packet::save packet(std::forward<Args>(args)...);
	std::size_t size = packet.size();

	auto rec = bp.alloc_out_packet(size, out);

	if(rec && packet.write(rec->data)) {
		return bp.create_out_packet(*rec, out);
	} else {
		bp.set_error(spssh_memory_error, "Could not allocate buffer for sending packet");
	}

	return false;
}

ssh_config test_configs[] =
	{
		{}
		,{.random_packet_padding = false}
		,{.max_out_buffer_size = 1024}
		,{.shrink_out_buffer_size = 0}
	};

TEST_CASE("ssh_binary_packet", "[unit]") {
	auto config_i = GENERATE(range(0, int(sizeof(test_configs)/sizeof(ssh_config))));

	ssh_config const& config = test_configs[config_i];
	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, test_log());
	bp_1.set_random(test_rand);

	REQUIRE(send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));
	CHECK(buf.used_size() > 0);

	ssh_binary_packet bp_2(config, test_log());
	bp_2.set_random(test_rand);

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

	ssh_config config{};
	string_out_buffer out_too_small{10};
	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, test_log());
	bp_1.set_random(test_rand);

	//put the packet in buffer
	REQUIRE(send_packet<ser::disconnect>(bp_1, out_too_small, 1, "test 1", "test 2"));
	CHECK(bp_1.error() == ssh_noerror);

	REQUIRE(!bp_1.send_pending(out_too_small));
	buf.data += out_too_small.data;
	buf.pos  += buf.data.size();
	REQUIRE(bp_1.send_pending(buf));

	ssh_binary_packet bp_2(config, test_log());
	bp_2.set_random(test_rand);

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

	string_out_buffer out_too_small{10};

	ssh_binary_packet bp_1(config, test_log());
	bp_1.set_random(test_rand);

	CHECK(!send_packet<ser::disconnect>(bp_1, out_too_small, 1, "test 1", "test 2"));
	CHECK(bp_1.error() == spssh_memory_error);
}

TEST_CASE("ssh_binary_packet crypto", "[unit]") {
	crypto_test_context ctx;
	ssh_config config;
	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	byte_vector key(32, std::byte{'A'});
	std::string_view iv = "0123456789AB";

	ssh_binary_packet bp_1(config, test_log());
	bp_1.set_random(test_rand);
	bp_1.set_output_crypto(ctx.construct_cipher(cipher_type::aes_256_gcm, cipher_dir::encrypt, key, to_span(iv), ctx.call), nullptr);

	REQUIRE(send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));
	CHECK(buf.used_size() > 0);

	ssh_binary_packet bp_2(config, test_log());
	bp_2.set_random(test_rand);
	bp_2.set_input_crypto(ctx.construct_cipher(cipher_type::aes_256_gcm, cipher_dir::decrypt, key, to_span(iv), ctx.call), nullptr);

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

TEST_CASE("ssh_binary_packet crypto 2", "[unit]") {
	crypto_test_context ctx;
	ssh_config config;
	string_io_buffer buf;
	std::byte temp_buf[1024] = {};

	byte_vector key(32, std::byte{'A'});
	std::string_view iv = "0123456789ABCDEF";

	ssh_binary_packet bp_1(config, test_log());
	bp_1.set_random(test_rand);
	bp_1.set_output_crypto(
		ctx.construct_cipher(cipher_type::aes_256_ctr, cipher_dir::encrypt, key, to_span(iv), ctx.call),
		ctx.construct_mac(mac_type::hmac_sha2_256, key, ctx.call));

	REQUIRE(send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));
	CHECK(buf.used_size() > 0);

	ssh_binary_packet bp_2(config, test_log());
	bp_2.set_random(test_rand);
	bp_2.set_input_crypto(
		ctx.construct_cipher(cipher_type::aes_256_ctr, cipher_dir::decrypt, key, to_span(iv), ctx.call),
		ctx.construct_mac(mac_type::hmac_sha2_256, key, ctx.call));

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


}