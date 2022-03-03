
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/common/packet_ser.hpp"
#include "ssh/common/packet_ser_impl.hpp"
#include "ssh/common/ssh_binary_packet.hpp"
#include "ssh/common/ssh_config.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

/*
	ssh_binary_packet(ssh_config const& config, logger& logger);

	ssh_error_code error() const;
	std::string error_message() const;

	void set_error(ssh_error_code code, std::string_view message);

public: //input
	bool set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac);
	bool try_decode_header(span in_data);
	span decrypt_packet(const_span in_data, span out_data);

public: //output
	std::optional<out_packet_record> alloc_out_packet(std::size_t data_size, out_buffer&);
	void create_out_packet(out_packet_record const&);
*/

namespace securepath::ssh::test {

template<typename Packet, typename... Args>
bool send_packet(ssh_binary_packet& bp, out_buffer& out, Args&&... args) {
	typename Packet::save packet(std::forward<Args>(args)...);
	std::size_t size = packet.size();

	auto rec = bp.alloc_out_packet(size, out);

	if(rec && packet.write(rec->data)) {
		bp.create_out_packet(*rec);
		out.commit(rec->size);
		return true;
	}

	return false;
}

//std::size_t max_out_buffer_size{128*1024};
//bool use_in_place_buffer{true};
//bool random_packet_padding{true};

TEST_CASE("ssh_binary_packet", "[unit]") {
	ssh_config config;
	string_io_buffer buf;
	stdout_logger logger;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, logger);
	REQUIRE(send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));

	ssh_binary_packet bp_2(config, logger);
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

TEST_CASE("ssh_binary_packet failing", "[unit]") {
	ssh_config config;
	ssh_config.max_out_buffer_size = 25;
	ssh_config.use_in_place_buffer = false;
	string_io_buffer buf;
	stdout_logger logger;
	std::byte temp_buf[1024] = {};

	ssh_binary_packet bp_1(config, logger);
	CHECK(!send_packet<ser::disconnect>(bp_1, buf, 1, "test 1", "test 2"));
	CHECK(bp_1.error() == );
}
}