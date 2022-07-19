
#include "log.hpp"
#include "configs.hpp"
#include "random.hpp"
#include "util.hpp"
#include "test_buffers.hpp"

#include "ssh/core/connection/channel.hpp"
#include "ssh/core/connection/ssh_connection.hpp"

#include "ssh/client/auth_service.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/server/ssh_server.hpp"
#include "test/util/server_auth_service.hpp"

#include <external/catch/catch.hpp>


namespace securepath::ssh::test {
namespace {

// currenly not implement:
// * flushing is not triggered from the ssh_transport layer
// * all buffers full condition not correctly handled (ie. the service should not handle the incoming packet in this case and return to retry after there is space in buffers again)


class test_data_channel : public channel {
public:
	test_data_channel(transport_base& transport, channel_side_info local, std::size_t out_data_size = 0)
	: channel(transport, local)
	, out_data_size(out_data_size)
	{
	}

	bool on_open(channel_side_info remote, const_span extra_data) override {
		bool res = channel::on_open(remote, extra_data);
		if(res) {
			// populate out data and initiate send
			out_data.resize(out_data_size, std::byte('A'));
			auto s = send_data(out_data);
			if(s) {
				out_data.erase(out_data.begin(), out_data.begin()+s);
			}
		}
		return res;
	}

	void on_send_more() override {
		if(!out_data.empty()) {
			auto s = send_data(out_data);
			if(s) {
				out_data.erase(out_data.begin(), out_data.begin()+s);
				log_.log(logger::debug_trace, "data left {} bytes", out_data.size());
			}
		}
	}

	void on_data(const_span s) override {
		in_data.insert(in_data.end(), s.begin(), s.end());
		channel::on_data(s);
	}

	std::size_t out_data_size;
	byte_vector in_data;
	byte_vector out_data;
};

class test_connection_service : public ssh_connection {
public:
	test_connection_service(ssh_transport& t, std::size_t out_data_size = 0)
	: ssh_connection(t)
	{
		add_channel_type("data-test", [=](transport_base& t, channel_side_info info)
		{
			return std::make_unique<test_data_channel>(t, info, out_data_size);
		});
	}

};

struct test_client : test_context, client_config, ssh_client {
	test_client()
	: test_context(test_log(), "[client] ")
	, client_config(test_client_config())
	, ssh_client(*this, slog, out_buf)
	{
		username = "test-user";
		password = "password";
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == connection_service_name) {
			return std::make_unique<test_connection_service>(*this);
		}
		return nullptr;
	}

	bool open_channel() {
		auto ch = static_cast<test_connection_service&>(*service_).open_channel("data-test");
		if(ch) {
			id = ch->id();
		}
		return ch != nullptr;
	}

	bool close_channel() {
		auto ch = get_channel();
		if(ch) {
			ch->send_close();
		}
		return ch != nullptr;
	}

	bool check_data(std::size_t size) const {
		auto ch = get_channel();
		if(ch) {
			if(ch->in_data != byte_vector(size, std::byte('A'))) {
				slog.log(logger::error, "bad in_data content [size={}]", ch->in_data.size());
				std::size_t pos = 0;
				for(bool keep_going = true; keep_going && pos < ch->in_data.size(); ++pos) {
					if(ch->in_data[pos] != std::byte('A')) {
						slog.log(logger::error, "first bad data in pos {} (value={})", pos, int(ch->in_data[pos]));
						keep_going = false;
					}
				}
				ch = nullptr;
			}
		}
		return ch != nullptr;
	}

	test_data_channel* get_channel() const {
		return static_cast<test_data_channel*>(
			static_cast<test_connection_service const&>(*service_).find_channel(id));
	}

	channel_id id{};
};


struct test_server : test_context, server_config, ssh_server {
	test_server(std::size_t out_data_size, std::size_t buffer_size = -1)
	: test_context(test_log(), "[server] ", buffer_size)
	, server_config(test_server_config())
	, ssh_server(*this, slog, out_buf)
	, out_data_size(out_data_size)
	{
		auth_data.add_password("test-user", "password");
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<server_test_auth_service>(*this, auth, std::move(auth_data));
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == connection_service_name) {
			return std::make_unique<test_connection_service>(*this, out_data_size);
		}
		return nullptr;
	}

	std::size_t out_data_size{};
	test_auth_data auth_data;
};
}

std::size_t data_sizes[] = {1, 11, 32*1024, 256*1024+1, 1024*1024*2, 1024*1024*9};
std::size_t const data_sizes_count = sizeof(data_sizes) / sizeof(*data_sizes);

std::uint32_t window_sizes[] = {1024, 256*1024, 2*1024*1024, std::uint32_t(-1)};
std::size_t const window_sizes_count = sizeof(window_sizes) / sizeof(*window_sizes);

std::uint32_t packet_sizes[] = {1024, 64*1024, 196*1024};
std::size_t const packet_sizes_count = sizeof(packet_sizes) / sizeof(*packet_sizes);


TEST_CASE("connection test", "[unit]") {
	auto data_i = GENERATE(range(0ul, data_sizes_count));
	auto window_i = GENERATE(range(0ul, window_sizes_count));
	auto packet_i = GENERATE(range(0ul, packet_sizes_count));
	CAPTURE(data_i);
	CAPTURE(window_i);
	CAPTURE(packet_i);

	std::size_t const data_size = data_sizes[data_i];
	test_server server(data_size);
	test_client client;

	server.channel.max_packet_size = packet_sizes[packet_i];
	client.channel.max_packet_size = packet_sizes[packet_i];
	server.channel.initial_window_size = window_sizes[window_i];
	client.channel.initial_window_size = window_sizes[window_i];

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);

	REQUIRE(client.open_channel());

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);

	REQUIRE(client.check_data(data_size));
	client.close_channel();

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);
	CHECK(!client.get_channel());
}

TEST_CASE("connection test - transport buffer full", "[unit]") {
	std::size_t const data_size = 2*1024*1024;

	test_server server(data_size, 128*1024);
	test_client client;

	REQUIRE(run(client, server));
	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);

	REQUIRE(client.open_channel());

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);

	REQUIRE(client.check_data(data_size));
	client.close_channel();

	REQUIRE(run(client, server));
}

}