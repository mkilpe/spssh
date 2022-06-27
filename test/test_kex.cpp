
#include "configs.hpp"
#include "crypto.hpp"
#include "random.hpp"
#include "test_buffers.hpp"

#include "ssh/common/util.hpp"
#include "ssh/core/kex.hpp"
#include "ssh/core/kex/ecdh.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/ssh_binary_packet.hpp"

namespace securepath::ssh::test {
namespace {

struct bp_to_transport_base : transport_base {
	ssh_error_code error() const override { return bp.error(); }
	std::string error_message() const override { return bp.error_message(); }
	void set_error(ssh_error_code code, std::string_view message = {}) override { bp.set_error(code, message); }
	void set_error_and_disconnect(ssh_error_code code, std::string_view message = {}) override { bp.set_error(code, message);}
	ssh_config const& config() const override { return bp.config(); }
	crypto_context const& crypto() const override { return ctx; }
	crypto_call_context call_context() const override { return ctx.call; }
	std::optional<out_packet_record> alloc_out_packet(std::size_t data_size) override { return bp.alloc_out_packet(data_size, out); }
	bool write_alloced_out_packet(out_packet_record const& r) override { return bp.create_out_packet(r, out); }
	const_span session_id() const override { return const_span{}; }

	bp_to_transport_base(ssh_binary_packet& bp, crypto_test_context& ctx, out_buffer& out)
	: bp(bp), ctx(ctx), out(out)
	{}

	ssh_binary_packet& bp;
	crypto_test_context& ctx;
	out_buffer& out;
};

struct test_context {
	test_context(logger& l, std::string tag, ssh_config c = {})
	: log(l, tag)
	, config(std::move(c))
	{
		bp.set_random(test_rand);

		//fill init_data
		init_data.local_ver = ssh_version{"2.0", "unit-test"};
		init_data.remote_ver = ssh_version{"2.0", "unit-test"};
		init_data.local_kexinit = byte_vector(64, std::byte{'A'});
		init_data.remote_kexinit = byte_vector(64, std::byte{'A'});
	}

	span data(test_context& in) {
		static std::byte buf[512];
		if(bp.try_decode_header(in.out_buf.get())) {
			return bp.decrypt_packet(in.out_buf.get(), buf);
		}
		return {};
	}

	session_logger log;
	ssh_config config;
	ssh_binary_packet bp{config, log};
	string_io_buffer out_buf;
	crypto_test_context ctx{log};
	kex_init_data init_data;
	bp_to_transport_base transport{bp, ctx, out_buf};
	kex_context kex_c{transport, init_data};
};
}

crypto_configuration const test_conf = {
	kex_type::curve25519_sha256, key_type::ssh_ed25519,
	{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none},
	{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}};

struct client_server_kex {
	client_server_kex() {
		c_kex = construct_kex(transport_side::client, kex_type::curve25519_sha256, c_context.kex_c);
		s_kex = construct_kex(transport_side::server, kex_type::curve25519_sha256, s_context.kex_c);

		REQUIRE(c_kex);
		REQUIRE(s_kex);

		c_kex->set_crypto_configuration(test_conf);
		s_kex->set_crypto_configuration(test_conf);

		CHECK(c_kex->state() == kex_state::none);

		CHECK(c_kex->initiate() == kex_state::inprogress);
		CHECK(s_kex->initiate() == kex_state::inprogress);
		CHECK(c_kex->state() == kex_state::inprogress);
		CHECK(s_kex->state() == kex_state::inprogress);
	}

	test_context c_context{test_log(), "[client] ", test_client_config()};
	test_context s_context{test_log(), "[server] ", test_server_config()};
	std::unique_ptr<kex> c_kex;
	std::unique_ptr<kex> s_kex;
};

void test_mac(mac& in, mac& out){
	byte_vector msg(64, std::byte{'A'});
	out.process(msg);
	in.process(msg);
	byte_vector r1(out.size());
	byte_vector r2(in.size());
	out.result(r1);
	in.result(r2);
	REQUIRE(r1 == r2);
}

void test_cipher(cipher& out, cipher& in) {
	byte_vector msg(out.block_size()*8, std::byte{'A'});
	byte_vector r1(msg.size());
	byte_vector r2(msg.size());
	out.process(msg, r1);
	in.process(r1, r2);
	REQUIRE(msg == r2);
}

void test_crypto_pairs(kex& k1, kex& k2) {
	std::optional<crypto_pair> k1_in = k1.construct_in_crypto_pair();
	std::optional<crypto_pair> k1_out = k1.construct_out_crypto_pair();
	std::optional<crypto_pair> k2_in = k2.construct_in_crypto_pair();
	std::optional<crypto_pair> k2_out = k2.construct_out_crypto_pair();

	REQUIRE(k1_in);
	REQUIRE(k1_out);
	REQUIRE(k2_in);
	REQUIRE(k2_out);
	REQUIRE(k1_in->cipher->block_size() == k2_out->cipher->block_size());
	REQUIRE(k2_in->cipher->block_size() == k1_out->cipher->block_size());
	REQUIRE(k1_in->cipher->is_aead() == k2_out->cipher->is_aead());
	REQUIRE(k2_in->cipher->is_aead() == k1_out->cipher->is_aead());

	test_cipher(*k1_out->cipher, *k2_in->cipher);
	test_cipher(*k2_out->cipher, *k1_in->cipher);
	if(k1_in->cipher->is_aead()) {
		REQUIRE(!k1_in->mac);
		REQUIRE(!k2_out->mac);
	} else {
		test_mac(*k2_out->mac, *k1_in->mac);
	}
	if(k2_in->cipher->is_aead()) {
		REQUIRE(!k2_in->mac);
		REQUIRE(!k1_out->mac);
	} else {
		test_mac(*k1_out->mac, *k2_in->mac);
	}
}

TEST_CASE("curve25519 sha256 kex", "[unit][crypto][kex]") {
	client_server_kex k;

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);
	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), k.c_context.data(k.s_context)) == kex_state::succeeded);
	CHECK(k.c_kex->state() == kex_state::succeeded);
	CHECK(k.s_kex->state() == kex_state::succeeded);
	CHECK(k.c_kex->error() == ssh_noerror);
	CHECK(k.s_kex->error() == ssh_noerror);

	CHECK(!is_zero(k.c_kex->session_id()));
	CHECK(compare_equal(k.c_kex->session_id(), k.s_kex->session_id()));

	CHECK(to_byte_vector(k.s_kex->server_host_key()) == to_byte_vector(k.c_kex->server_host_key()));
	CHECK(k.c_kex->server_host_key().valid());
	test_crypto_pairs(*k.c_kex, *k.s_kex);
}

TEST_CASE("curve25519 sha256 kex different version", "[unit][crypto][kex]") {
	client_server_kex k;

	// change the client local ssh version
	k.c_context.init_data.local_ver.ssh = "1.0";

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);
	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), k.c_context.data(k.s_context)) == kex_state::error);
	CHECK(k.c_kex->state() == kex_state::error);
	CHECK(k.s_kex->state() == kex_state::succeeded);
	CHECK(k.c_kex->error() == ssh_key_exchange_failed);
	CHECK(k.s_kex->error() == ssh_noerror);
}

TEST_CASE("curve25519 sha256 kex bad client packet 1", "[unit][crypto][kex]") {
	client_server_kex k;
	byte_vector buf;
	// X25519 public key is 32 bytes, so this one is too short
	std::vector too_short(31, std::byte{'A'});
	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_init>(buf, to_string_view(too_short)));
	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), buf) == kex_state::error);
	CHECK(k.s_kex->state() == kex_state::error);
}

TEST_CASE("curve25519 sha256 kex bad client packet 2", "[unit][crypto][kex]") {
	client_server_kex k;
	byte_vector buf;
	// right size but all zeroes
	std::vector bad(32, std::byte{0});
	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_init>(buf, to_string_view(bad)));
	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), buf) == kex_state::error);
	CHECK(k.s_kex->state() == kex_state::error);
}

TEST_CASE("curve25519 sha256 kex bad server packet 1", "[unit][crypto][kex]") {
	client_server_kex k;

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);

	ser::kex_ecdh_reply::load packet(ser::match_type_t, k.c_context.data(k.s_context));
	REQUIRE(packet);
	auto & [host_key, server_eph_key, sig] = packet;

	byte_vector buf;
	// right size but all zeroes
	std::vector bad(32, std::byte{0});
	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_reply>(buf, host_key, to_string_view(bad), sig));

	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), buf) == kex_state::error);
	CHECK(k.c_kex->state() == kex_state::error);
}

TEST_CASE("curve25519 sha256 kex bad server packet 2", "[unit][crypto][kex]") {
	client_server_kex k;

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);

	ser::kex_ecdh_reply::load packet(ser::match_type_t, k.c_context.data(k.s_context));
	REQUIRE(packet);
	auto & [host_key, server_eph_key, sig] = packet;

	byte_vector buf;
	std::string bad_host_key(host_key);
	//flip a bit
	bad_host_key[bad_host_key.size()/2] ^= 0x01;

	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_reply>(buf, bad_host_key, server_eph_key, sig));

	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), buf) == kex_state::error);
	CHECK(k.c_kex->state() == kex_state::error);
}

}