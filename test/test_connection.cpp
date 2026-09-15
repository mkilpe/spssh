
#include "log.hpp"
#include "configs.hpp"
#include "random.hpp"
#include "util.hpp"
#include "test_buffers.hpp"

#include "ssh/core/connection/channel.hpp"
#include "ssh/core/connection/ssh_connection.hpp"

#include "ssh/client/auth_service.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/server/ssh_server.hpp"
#include "test/util/server_auth_service.hpp"

#include <external/catch/catch.hpp>


namespace securepath::ssh::test {
namespace {

// currenly not implement:
// * flushing is not triggered from the ssh_transport layer
// * all buffers full condition not correctly handled (ie. the service should not handle the incoming packet in this case and return to retry after there is space in buffers again)


// true if the data holds exactly one kexinit packet with nothing trailing it
bool is_single_kexinit(byte_vector const& data) {
	ser::kexinit::load packet(ser::match_type_t, data);
	return packet && packet.size() == data.size();
}

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

	bool on_data(const_span s) override {
		in_data.insert(in_data.end(), s.begin(), s.end());
		return channel::on_data(s);
	}

	std::size_t out_data_size;
	byte_vector in_data;
	byte_vector out_data;
};

// answers every incoming chunk with the same data
class echo_channel : public channel {
public:
	using channel::channel;

	bool on_data(const_span s) override {
		send_data(s);
		return channel::on_data(s);
	}
};

class test_connection_service : public ssh_connection {
public:
	test_connection_service(ssh_transport& t, std::size_t out_data_size = 0, bool echo = false)
	: ssh_connection(t)
	{
		add_channel_type("data-test", [=](transport_base& t, channel_side_info info)
		{
			return std::make_unique<test_data_channel>(t, info, out_data_size);
		});
		// the echoing side gets an echo channel, the other side a plain recording channel
		add_channel_type("echo-test", [=](transport_base& t, channel_side_info info) -> std::unique_ptr<channel>
		{
			if(echo) {
				return std::make_unique<echo_channel>(t, info);
			}
			return std::make_unique<test_data_channel>(t, info);
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

	bool open_channel(std::string_view type = "data-test") {
		auto ch = static_cast<test_connection_service&>(*service_).open_channel(type);
		if(ch) {
			ids.push_back(ch->id());
		}
		return ch != nullptr;
	}

	bool close_channel(std::size_t id = 0) {
		auto ch = get_channel(id);
		if(ch) {
			ch->send_close();
		}
		return ch != nullptr;
	}

	bool check_data(std::size_t size, std::size_t id = 0) const {
		auto ch = get_channel(id);
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

	bool local_kexinit_is_single_packet() const { return is_single_kexinit(kex_data().local_kexinit); }
	bool remote_kexinit_is_single_packet() const { return is_single_kexinit(kex_data().remote_kexinit); }
	byte_vector local_kexinit() const { return kex_data().local_kexinit; }

	// non-kex packets received while in key exchange; on the side that did not initiate the rekey these can
	// only be packets the peer sent after its own kexinit, which rfc 4253 forbids
	handler_result handle_transport_packet(ssh_packet_type type, const_span payload) override {
		if(state() == ssh_state::kex && !is_kex_packet(type)) {
			++non_kex_packets_during_kex;
		}
		return ssh_client::handle_transport_packet(type, payload);
	}
	// an exchange must never start while output is still pending, otherwise its packets could not be sent
	void on_state_change(ssh_state old_s, ssh_state new_s) override {
		if(new_s == ssh_state::kex && !can_start_kex()) {
			++kex_started_congested;
		}
		if(new_s == ssh_state::transport) {
			// with strict kex the remote's newkeys, which completes the exchange, restarts the incoming sequence
			max_in_seq_at_done = std::max(max_in_seq_at_done, in_sequence());
		}
		ssh_client::on_state_change(old_s, new_s);
	}

	test_data_channel* get_channel(std::size_t id = 0) const {
		assert(id < ids.size());
		return static_cast<test_data_channel*>(
			static_cast<test_connection_service const&>(*service_).find_channel(ids[id]));
	}

	std::vector<channel_id> ids{};
	std::size_t non_kex_packets_during_kex{};
	std::size_t kex_started_congested{};
	std::uint32_t max_in_seq_at_done{};
};


struct test_server : test_context, server_config, ssh_server {
	test_server(std::size_t out_data_size, std::size_t buffer_size = -1, server_config conf = test_server_config())
	: test_context(test_log(), "[server] ", buffer_size)
	, server_config(std::move(conf))
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
			return std::make_unique<test_connection_service>(*this, out_data_size, echo);
		}
		return nullptr;
	}

	bool local_kexinit_is_single_packet() const { return is_single_kexinit(kex_data().local_kexinit); }
	bool remote_kexinit_is_single_packet() const { return is_single_kexinit(kex_data().remote_kexinit); }
	byte_vector local_kexinit() const { return kex_data().local_kexinit; }

	// non-kex packets received while in key exchange; on the side that did not initiate the rekey these can
	// only be packets the peer sent after its own kexinit, which rfc 4253 forbids
	handler_result handle_transport_packet(ssh_packet_type type, const_span payload) override {
		if(state() == ssh_state::kex && !is_kex_packet(type)) {
			++non_kex_packets_during_kex;
		}
		return ssh_server::handle_transport_packet(type, payload);
	}
	// an exchange must never start while output is still pending, otherwise its packets could not be sent
	void on_state_change(ssh_state old_s, ssh_state new_s) override {
		if(new_s == ssh_state::kex && !can_start_kex()) {
			++kex_started_congested;
		}
		if(new_s == ssh_state::transport) {
			// with strict kex the remote's newkeys, which completes the exchange, restarts the incoming sequence
			max_in_seq_at_done = std::max(max_in_seq_at_done, in_sequence());
		}
		ssh_server::on_state_change(old_s, new_s);
	}

	std::size_t out_data_size{};
	test_auth_data auth_data;
	std::size_t non_kex_packets_during_kex{};
	std::size_t kex_started_congested{};
	std::uint32_t max_in_seq_at_done{};
	bool echo{};
};
}

std::size_t data_sizes[] = {1, 11, 32*1024, 256*1024+1, 1024*1024*2, 1024*1024*9};
std::size_t const data_sizes_count = sizeof(data_sizes) / sizeof(*data_sizes);

std::uint32_t window_sizes[] = {1024, 256*1024, 2*1024*1024, std::uint32_t(-1)};
std::size_t const window_sizes_count = sizeof(window_sizes) / sizeof(*window_sizes);

std::uint32_t packet_sizes[] = {1024, 64*1024, 196*1024};
std::size_t const packet_sizes_count = sizeof(packet_sizes) / sizeof(*packet_sizes);


TEST_CASE("connection test", "[unit]") {
	auto data_i = GENERATE(range(std::size_t{}, data_sizes_count));
	auto window_i = GENERATE(range(std::size_t{}, window_sizes_count));
	auto packet_i = GENERATE(range(std::size_t{}, packet_sizes_count));
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

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	REQUIRE(client.open_channel());

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	REQUIRE(client.check_data(data_size));
	client.close_channel();

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(!client.get_channel());
}


// this is to test the flushing after buffers full and some space comes available
TEST_CASE("connection test - transport buffer full", "[unit]") {
	std::size_t const data_size = 2*1024*1024;

	test_server server(data_size, 128*1024);
	test_client client;

	REQUIRE(run(client, server));
	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	REQUIRE(client.open_channel());

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	REQUIRE(client.check_data(data_size));
	client.close_channel();

	REQUIRE(run(client, server));
}

TEST_CASE("connection test - multi", "[unit]") {
	std::size_t const channels = 10;
	std::size_t const data_size = 2*1024*1024;

	test_server server(data_size, 128*1024);
	test_client client;

	REQUIRE(run(client, server));
	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	for(std::size_t i = 0; i != channels; ++i) {
		REQUIRE(client.open_channel());
	}

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	for(std::size_t i = 0; i != channels; ++i) {
		REQUIRE(client.check_data(data_size, i));
		client.close_channel(i);
	}

	REQUIRE(run(client, server));
}


TEST_CASE("connection test - rekey", "[unit]") {
	std::size_t const data_size = 10*1024*1024;

	server_config conf = test_server_config();
	conf.rekey_data_interval = 1024*1024;

	test_server server(data_size, 128*1024, std::move(conf));
	test_client client;

	REQUIRE(run(client, server));
	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	auto sid_span = server.session_id();
	byte_vector sid{sid_span.begin(), sid_span.end()};
	auto kexinit_before = client.local_kexinit();

	REQUIRE(client.open_channel());

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	auto sid_span2 = server.session_id();
	byte_vector sid2{sid_span2.begin(), sid_span2.end()};
	CHECK(sid == sid2);

	// every rekey must send a fresh kexinit, not the accumulated history of the earlier ones
	CHECK(client.local_kexinit_is_single_packet());
	CHECK(server.local_kexinit_is_single_packet());
	CHECK(client.remote_kexinit_is_single_packet());
	CHECK(server.remote_kexinit_is_single_packet());

	// the rekey happened, and the server (initiator) sent only kex packets between its kexinit and newkeys
	CHECK(client.local_kexinit() != kexinit_before);
	CHECK(client.non_kex_packets_during_kex == 0);
	CHECK(server.kex_started_congested == 0);
	CHECK(client.kex_started_congested == 0);
	// strict kex: every one of the exchanges restarted the sequence numbers
	CHECK(client.max_in_seq_at_done == 0);
	CHECK(server.max_in_seq_at_done == 0);

	REQUIRE(client.check_data(data_size));
	client.close_channel();

	REQUIRE(run(client, server));
}

TEST_CASE("connection test - rekey initiated by client", "[unit]") {
	std::size_t const data_size = 10*1024*1024;

	test_server server(data_size, 128*1024);
	test_client client;
	client.rekey_data_interval = 1024*1024;

	REQUIRE(run(client, server));
	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	auto kexinit_before = server.local_kexinit();

	REQUIRE(client.open_channel());

	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	// the rekey happened, and the client (initiator) sent only kex packets between its kexinit and newkeys
	CHECK(server.local_kexinit() != kexinit_before);
	CHECK(server.non_kex_packets_during_kex == 0);
	CHECK(server.kex_started_congested == 0);
	CHECK(client.kex_started_congested == 0);

	REQUIRE(client.check_data(data_size));
	client.close_channel();

	REQUIRE(run(client, server));
}

TEST_CASE("connection test - rekey with congested output", "[unit]") {
	// a short rekey interval with the default large window: every exchange ends with a long queue of held channel
	// data, and the next exchange is already due while that queue is still draining into a full output buffer
	std::size_t const data_size = 6*1024*1024;

	server_config conf = test_server_config();
	conf.rekey_data_interval = 256*1024;

	test_server server(data_size, 128*1024, std::move(conf));
	test_client client;

	REQUIRE(run(client, server));
	REQUIRE(client.open_channel());
	REQUIRE(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(server.kex_started_congested == 0);
	REQUIRE(client.check_data(data_size));

	client.close_channel();
	REQUIRE(run(client, server));
}

namespace {

// the server starts a rekey while the client, which never gets to see the kexinit, keeps sending data that the
// server's echo channel has to answer; returns how many chunks were sent before the loop ended
int feed_echo_server_during_rekey(test_client& client, test_server& server, std::size_t chunk_size, int max_chunks, bool& rekey_started) {
	byte_vector chunk(chunk_size, std::byte{'E'});
	int sent = 0;
	for(; sent != max_chunks && server.state() != ssh_state::disconnected; ++sent) {
		REQUIRE(client.get_channel()->send_data(chunk) == chunk.size());
		// only the server runs, so the client never answers the kexinit
		server.process(client.out_buf);
		rekey_started = rekey_started || server.state() == ssh_state::kex;
	}
	return sent;
}

}

TEST_CASE("connection test - remote never completes the rekey", "[unit]") {
	server_config conf = test_server_config();
	conf.rekey_data_interval = 64*1024;
	conf.max_kex_pending_out_size = 256*1024;

	test_server server(0, -1, std::move(conf));
	server.echo = true;
	test_client client;

	REQUIRE(run(client, server));
	REQUIRE(client.open_channel("echo-test"));
	REQUIRE(run(client, server));
	REQUIRE(server.state() == ssh_state::transport);

	bool rekey_started = false;
	int sent = feed_echo_server_during_rekey(client, server, 16*1024, 64, rekey_started);

	// the held answers reached the limit, so the server gave up on the remote
	CHECK(rekey_started);
	CHECK(sent < 64);
	CHECK(server.state() == ssh_state::disconnected);
	CHECK(server.error() == ssh_error_code::ssh_key_exchange_failed);
}

TEST_CASE("connection test - remote completes the rekey late", "[unit]") {
	server_config conf = test_server_config();
	conf.rekey_data_interval = 64*1024;

	test_server server(0, -1, std::move(conf));
	server.echo = true;
	test_client client;

	REQUIRE(run(client, server));
	REQUIRE(client.open_channel("echo-test"));
	REQUIRE(run(client, server));

	bool rekey_started = false;
	int sent = feed_echo_server_during_rekey(client, server, 16*1024, 32, rekey_started);
	CHECK(rekey_started);
	CHECK(sent == 32);
	CHECK(server.state() == ssh_state::kex);

	// now the client answers, the exchange completes and every held answer arrives
	REQUIRE(run(client, server));
	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.get_channel()->in_data == byte_vector(32*16*1024, std::byte{'E'}));
	CHECK(server.kex_started_congested == 0);
	CHECK(client.non_kex_packets_during_kex == 0);
}

}
