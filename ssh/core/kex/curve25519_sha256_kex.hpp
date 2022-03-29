#ifndef SPSSH_CORE_KEX_CURVE25519_SHA256_HEADER
#define SPSSH_CORE_KEX_CURVE25519_SHA256_HEADER

#include "ecdh.hpp"
#include "ssh/core/kex.hpp"
#include "ssh/core/ssh_config.hpp"
#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh {

struct curve25519_sha256_kex_base : public kex {
	curve25519_sha256_kex_base(kex_context kex_c)
	: context_(kex_c)
	, x25519_(context_.ccontext().construct_key_exchange(key_exchange_type::X25519, context_.call_context()))
	{
	}

	kex_type type() const override {
		return kex_type::curve25519_sha256;
	}

	void set_crypto_configuration(crypto_configuration conf) override {
		conf_ = conf;
	}

protected:
	kex_context context_;
	crypto_configuration conf_;
	std::unique_ptr<key_exchange> x25519_;
};

struct curve25519_sha256_kex_client : public curve25519_sha256_kex_base {
	curve25519_sha256_kex_client(kex_context kex_c)
	: curve25519_sha256_kex_base(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex_client");
	}

	kex_state initiate() override {
		if(x25519_) {
			if(context_.send_packet<ser::kex_ecdh_init>(to_string_view(x25519_->public_key()))) {
				return kex_state::inprogress;
			}
		}
		return kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		return kex_state::error;
	}

};

struct curve25519_sha256_kex_server : public curve25519_sha256_kex_base {
	curve25519_sha256_kex_server(kex_context kex_c)
	: curve25519_sha256_kex_base(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex_server");
	}

	kex_state initiate() override {
		return x25519_ ? kex_state::inprogress : kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		return kex_state::error;
	}

};

}

#endif