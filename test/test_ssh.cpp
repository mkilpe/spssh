
#include "config.hpp"
#include "configs.hpp"
#include "util.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/server/ssh_server.hpp"
#include "test/util/server_auth_service.hpp"

#if defined(USE_NETTLE) && defined(USE_CRYPTOPP)
#	include "ssh/crypto/nettle/crypto_context.hpp"
#	include "ssh/crypto/cryptopp/crypto_context.hpp"
#endif

#include <external/catch/catch.hpp>

namespace securepath::ssh::test {
namespace {

struct test_client : test_context, client_config, ssh_client {
	test_client(logger& l, client_config c = {}, crypto_context ccontext = default_crypto_context())
	: test_context(l, "[client] ")
	, client_config{std::move(c)}
	, ssh_client(*this, slog, out_buf, std::move(ccontext))
	{
		side = transport_side::client;
	}

	void set_test_auth() {
		username = "test";
		password = "some";
		service = "dummy-service";
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	bool handle_basic_packets(ssh_packet_type type, const_span payload) override {
		if(type == ssh_unimplemented) {
			++unimplemented_received;
		}
		return ssh_client::handle_basic_packets(type, payload);
	}

	bool strict() const { return strict_kex_negotiated(); }
	byte_vector local_kexinit_packet() const { return kex_data().local_kexinit; }

	// the sequence numbers at the moment an exchange completes; with strict kex both restart from zero
	void on_state_change(ssh_state old_s, ssh_state new_s) override {
		if(new_s == ssh_state::transport) {
			++kex_done_count;
			seq_in_at_done = in_sequence();
			seq_out_at_done = out_sequence();
		}
		ssh_client::on_state_change(old_s, new_s);
	}

	int kex_done_count{};
	std::uint32_t seq_in_at_done{};
	std::uint32_t seq_out_at_done{};

	std::size_t unimplemented_received{};
};

struct test_server : test_context, server_config, ssh_server {
	test_server(logger& l, ssh_config c = {}, crypto_context ccontext = default_crypto_context())
	: test_context(l, "[server] ")
	, server_config{std::move(c)}
	, ssh_server(*this, slog, out_buf, std::move(ccontext))
	{
		side = transport_side::server;
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<server_test_auth_service>(*this, auth, std::move(auth_data));
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	void set_test_auth() {
		//void add_pk(std::string const& user, std::string fp)
		//void add_password(std::string const& user, std::string password);
		auth_data.add_password("test", "some");
		auth.service_auth["dummy-service"] = req_auth{};
	}

	bool strict() const { return strict_kex_negotiated(); }
	byte_vector local_kexinit_packet() const { return kex_data().local_kexinit; }

	// the sequence numbers at the moment an exchange completes; with strict kex both restart from zero
	void on_state_change(ssh_state old_s, ssh_state new_s) override {
		if(new_s == ssh_state::transport) {
			++kex_done_count;
			seq_in_at_done = in_sequence();
			seq_out_at_done = out_sequence();
		}
		ssh_server::on_state_change(old_s, new_s);
	}

	int kex_done_count{};
	std::uint32_t seq_in_at_done{};
	std::uint32_t seq_out_at_done{};

	test_auth_data auth_data;
};

// service that lets the test choose the handler_result for a couple of sentinel packet types and records
// what payload it was handed, so the transport's consume and payload-lifetime behaviour can be observed
struct probe_service : ssh_service {
	std::string_view name() const override { return "dummy-service"; }
	service_state state() const override { return service_state::inprogress; }
	bool init() override { return true; }
	handler_result process(ssh_packet_type type, const_span payload) override {
		last_type = std::uint8_t(type);
		last_payload.assign(payload.begin(), payload.end());
		++calls;
		handler_result res = handler_result::handled;
		if(std::uint8_t(type) == pending_type && !resumed) {
			res = handler_result::pending;
		} else if(std::uint8_t(type) == unknown_type) {
			res = handler_result::unknown;
		}
		return res;
	}

	static constexpr std::uint8_t unknown_type = 200;
	static constexpr std::uint8_t known_type = 201;
	static constexpr std::uint8_t pending_type = 202;

	bool resumed{};
	int calls{};
	std::uint8_t last_type{};
	byte_vector last_payload;
};

struct probe_server : test_server {
	using test_server::test_server;

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			auto s = std::make_unique<probe_service>();
			probe = s.get();
			return s;
		}
		return nullptr;
	}

	probe_service* probe{};
};

// in_buffer that relocates its storage whenever bytes are appended (like a growing std::string) and poisons
// the previous allocation, so any span kept from before the append reads 0xFF instead of the real bytes
class relocating_in_buffer : public in_buffer {
public:
	span get() override {
		return live_ ? span{live_->data(), live_->size()} : span{};
	}

	void consume(std::size_t size) override {
		assert(live_ && size <= live_->size());
		live_->erase(live_->begin(), live_->begin() + size);
	}

	void add(const_span s) {
		auto fresh = std::make_unique<byte_vector>();
		if(live_) {
			fresh->assign(live_->begin(), live_->end());
		}
		fresh->insert(fresh->end(), s.begin(), s.end());
		if(live_) {
			std::fill(live_->begin(), live_->end(), std::byte{0xFF});
			graveyard_.push_back(std::move(live_));
		}
		live_ = std::move(fresh);
	}

	bool empty() const { return !live_ || live_->empty(); }

private:
	std::unique_ptr<byte_vector> live_;
	// old allocations are kept alive but poisoned, so a stale span reads defined 0xFF rather than freed memory
	std::vector<std::unique_ptr<byte_vector>> graveyard_;
};
}

TEST_CASE("ssh test", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}

TEST_CASE("ssh test guess", "[unit]") {
	server_config s = test_server_config();
	s.guess_kex_packet = true;
	client_config c = test_client_config();
	c.guess_kex_packet = true;
	test_server server(test_log(), std::move(s));
	test_client client(test_log(), std::move(c));

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());
}

TEST_CASE("ssh failing version exchange", "[unit]") {
	test_server server(test_log());
	client_config c = test_client_config();
	test_client client(test_log(), client_config{ssh_config{.my_version = ssh_version{.ssh="1.0"}}});

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);
	// the ssh_transport tries to send kexinit before reading the disconnect packet
	CHECK(client.error() != ssh_error_code::ssh_noerror);
	CHECK(server.error() == ssh_error_code::ssh_protocol_version_not_supported);
}


TEST_CASE("ssh no kex", "[unit]") {
	test_server server(test_log());
	test_client client(test_log());

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_error_code::ssh_key_exchange_failed);
	CHECK(server.error() == ssh_error_code::ssh_key_exchange_failed);
}

TEST_CASE("ssh failing auth (bad service)", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	client.set_test_auth();

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_error_code::ssh_service_not_available);
	CHECK(server.error() == ssh_error_code::ssh_service_not_available);
}


TEST_CASE("ssh failing auth (no method)", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	client.set_test_auth();
	server.auth.service_auth["dummy-service"] = req_auth{};
	server.auth.num_of_tries = 1;

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);
}

TEST_CASE("ssh test 2", "[unit]") {
	test_server server(test_log(), test_server_aes_ctr_config());
	test_client client(test_log(), test_client_aes_ctr_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}

#if defined(USE_NETTLE) && defined(USE_CRYPTOPP)
TEST_CASE("ssh crypto interoperability 1", "[unit]") {
	test_server server(test_log(), test_server_config(), nettle::create_nettle_context());
	test_client client(test_log(), test_client_config(), cryptopp::create_cryptopp_context());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}

TEST_CASE("ssh crypto interoperability 2", "[unit]") {
	test_server server(test_log(), test_server_config(), cryptopp::create_cryptopp_context());
	test_client client(test_log(), test_client_config(), nettle::create_nettle_context());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}
#endif


TEST_CASE("ssh test dh kex", "[unit]") {
	test_server server(test_log(), test_server_dh_kex_config());
	test_client client(test_log(), test_client_dh_kex_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}

TEST_CASE("ssh unimplemented packet is consumed", "[unit]") {
	probe_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));
	REQUIRE(client.state() == ssh_state::transport);
	REQUIRE(server.state() == ssh_state::transport);
	REQUIRE(server.probe != nullptr);

	// a packet the service does not implement, followed by one it does
	byte_vector unknown_pkt{std::byte(probe_service::unknown_type), std::byte('a'), std::byte('b')};
	byte_vector known_pkt{std::byte(probe_service::known_type), std::byte('c'), std::byte('d')};
	REQUIRE(client.send_payload(unknown_pkt));
	REQUIRE(client.send_payload(known_pkt));

	// bounded pump so that a regression (packet never consumed, re-dispatched forever) cannot hang the suite
	for(int i = 0; i < 20; ++i) {
		client.process(server.out_buf);
		server.process(client.out_buf);
	}

	CHECK(server.state() == ssh_state::transport);
	// the unimplemented packet must be consumed, so the following packet gets handled exactly once
	CHECK(server.probe->last_type == probe_service::known_type);
	CHECK(server.probe->calls == 2);
}

TEST_CASE("ssh pending packet survives input buffer relocation", "[unit]") {
	probe_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));
	REQUIRE(server.state() == ssh_state::transport);
	REQUIRE(server.probe != nullptr);

	// the payload the service will hold as pending and later check
	byte_vector body{std::byte('p'), std::byte('a'), std::byte('y'), std::byte('l'), std::byte('o'), std::byte('a'), std::byte('d')};
	byte_vector pending_pkt{std::byte(probe_service::pending_type)};
	pending_pkt.insert(pending_pkt.end(), body.begin(), body.end());
	REQUIRE(client.send_payload(pending_pkt));

	relocating_in_buffer srv_in;
	auto out = client.out_buf.get();
	srv_in.add(out);
	client.out_buf.consume(out.size());

	// first round: the service holds the packet as pending, so it stays in the buffer
	server.process(srv_in);
	REQUIRE(server.probe->calls == 1);
	CHECK(server.probe->last_type == probe_service::pending_type);
	CHECK(!srv_in.empty());

	// more data arrives; the buffer relocates and poisons the storage the pending payload pointed at
	byte_vector more{std::byte(probe_service::known_type), std::byte('x')};
	REQUIRE(client.send_payload(more));
	auto out2 = client.out_buf.get();
	srv_in.add(out2);
	client.out_buf.consume(out2.size());

	// resume: with the payload re-derived from the current buffer the content is intact; a stale span reads poison
	server.probe->resumed = true;
	server.process(srv_in);

	REQUIRE(server.probe->calls == 2);
	CHECK(server.probe->last_type == probe_service::pending_type);
	CHECK(server.probe->last_payload == body);
	CHECK(server.state() == ssh_state::transport);
}

TEST_CASE("ssh userauth request after success is silently ignored", "[unit]") {
	probe_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));
	REQUIRE(server.user_authenticated());
	REQUIRE(server.probe != nullptr);

	// authentication messages after the authentication has already succeeded: a userauth request, an info
	// response and a method specific message, followed by a normal packet
	byte_vector auth_req{std::byte(ssh_userauth_request), std::byte('x')};
	byte_vector info_resp{std::byte(ssh_userauth_info_response), std::byte('x')};
	byte_vector method_specific{std::byte(60), std::byte('x')};
	byte_vector known_pkt{std::byte(probe_service::known_type), std::byte('y')};
	REQUIRE(client.send_payload(auth_req));
	REQUIRE(client.send_payload(info_resp));
	REQUIRE(client.send_payload(method_specific));
	REQUIRE(client.send_payload(known_pkt));

	for(int i = 0; i < 20; ++i) {
		client.process(server.out_buf);
		server.process(client.out_buf);
	}

	// rfc 4252 sections 5.1 and 5.3: ignored silently, so no unimplemented reply and the service never sees them
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.unimplemented_received == 0);
	CHECK(server.probe->calls == 1);
	CHECK(server.probe->last_type == probe_service::known_type);
}

namespace {

std::vector<std::string> kex_names_of(byte_vector const& kexinit) {
	ser::kexinit::load p(ser::match_type_t, kexinit);
	REQUIRE(p);
	auto& [cookie, kexes, host_keys, c1, c2, m1, m2, z1, z2, l1, l2, first, reserved] = p;
	return std::vector<std::string>(kexes.begin(), kexes.end());
}

bool has_name(std::vector<std::string> const& names, std::string_view name) {
	return std::find(names.begin(), names.end(), name) != names.end();
}

}

TEST_CASE("strict kex negotiated and sequence numbers reset", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	// both offer it, standard and pre-standard name, and both see the other offering it
	auto client_names = kex_names_of(client.local_kexinit_packet());
	auto server_names = kex_names_of(server.local_kexinit_packet());
	CHECK(has_name(client_names, "kex-strict-c"));
	CHECK(has_name(client_names, "kex-strict-c-v00@openssh.com"));
	CHECK(has_name(server_names, "kex-strict-s"));
	CHECK(has_name(server_names, "kex-strict-s-v00@openssh.com"));
	CHECK(client.strict());
	CHECK(server.strict());

	// and both directions restarted from zero right after newkeys
	REQUIRE(client.kex_done_count == 1);
	REQUIRE(server.kex_done_count == 1);
	CHECK(client.seq_in_at_done == 0);
	CHECK(client.seq_out_at_done == 0);
	CHECK(server.seq_in_at_done == 0);
	CHECK(server.seq_out_at_done == 0);
}

TEST_CASE("strict kex off when only one side offers it", "[unit]") {
	server_config sconf = test_server_config();
	client_config cconf = test_client_config();
	bool server_offers = true;
	SECTION("server does not offer") { sconf.strict_kex = false; server_offers = false; }
	SECTION("client does not offer") { cconf.strict_kex = false; }

	test_server server(test_log(), std::move(sconf));
	test_client client(test_log(), std::move(cconf));
	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	CHECK(!client.strict());
	CHECK(!server.strict());
	CHECK(has_name(kex_names_of(server.local_kexinit_packet()), "kex-strict-s") == server_offers);

	// no reset, so the counters keep counting from the start of the connection
	REQUIRE(client.kex_done_count == 1);
	CHECK(client.seq_in_at_done > 0);
	CHECK(client.seq_out_at_done > 0);
	CHECK(server.seq_in_at_done > 0);
	CHECK(server.seq_out_at_done > 0);
}

TEST_CASE("strict kex rejects ignore during the initial exchange", "[unit]") {
	server_config sconf = test_server_config();
	bool strict = true;
	SECTION("strict") {}
	SECTION("not strict") { sconf.strict_kex = false; strict = false; }

	test_server server(test_log(), std::move(sconf));
	test_client client(test_log(), test_client_config());
	server.set_test_auth();
	client.set_test_auth();

	// versions exchanged and both kexinits sent, then an ignore packet while the exchange is still running
	client.process(server.out_buf);
	server.process(client.out_buf);
	client.process(server.out_buf);
	REQUIRE(client.state() == ssh_state::kex);
	client.send_ignore(10);

	if(strict) {
		CHECK(!run(client, server));
		CHECK(server.state() == ssh_state::disconnected);
		CHECK(server.error() == ssh_error_code::ssh_protocol_error);
	} else {
		CHECK(run(client, server));
		CHECK(server.user_authenticated());
	}
}

TEST_CASE("strict kex requires kexinit to be the first packet", "[unit]") {
	server_config sconf = test_server_config();
	bool strict = true;
	SECTION("strict") {}
	SECTION("not strict") { sconf.strict_kex = false; strict = false; }

	test_server server(test_log(), std::move(sconf));
	test_client client(test_log(), test_client_config());
	server.set_test_auth();
	client.set_test_auth();

	// the client has sent its version only, then an ignore packet goes out before its kexinit
	client.process(server.out_buf);
	REQUIRE(client.state() == ssh_state::version_exchange);
	client.send_ignore(10);

	if(strict) {
		CHECK(!run(client, server));
		CHECK(server.state() == ssh_state::disconnected);
		CHECK(server.error() == ssh_error_code::ssh_protocol_error);
	} else {
		CHECK(run(client, server));
		CHECK(server.user_authenticated());
	}
}

TEST_CASE("required strict kex refuses a remote that does not offer it", "[unit]") {
	server_config sconf = test_server_config();
	client_config cconf = test_client_config();
	bool refused = false;
	SECTION("server requires, client offers") { sconf.require_strict_kex = true; }
	SECTION("server requires, client does not offer") { sconf.require_strict_kex = true; cconf.strict_kex = false; refused = true; }
	SECTION("client requires, server does not offer") { cconf.require_strict_kex = true; sconf.strict_kex = false; refused = true; }

	test_server server(test_log(), std::move(sconf));
	test_client client(test_log(), std::move(cconf));
	server.set_test_auth();
	client.set_test_auth();

	if(refused) {
		CHECK(!run(client, server));
		CHECK(client.state() == ssh_state::disconnected);
		CHECK(server.state() == ssh_state::disconnected);
		CHECK((client.error() == ssh_error_code::ssh_key_exchange_failed || server.error() == ssh_error_code::ssh_key_exchange_failed));
	} else {
		CHECK(run(client, server));
		CHECK(client.strict());
		CHECK(server.strict());
		CHECK(server.user_authenticated());
	}
}

}
