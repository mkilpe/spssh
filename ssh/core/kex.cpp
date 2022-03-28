#include "kex.hpp"
#include "ssh_config.hpp"

#include <ostream>

namespace securepath::ssh {

struct curve25519_sha256_kex : public kex {
	curve25519_sha256_kex(kex_context kex_c)
	: context_(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex");
	}

	kex_type type() const override {
		return kex_type::curve25519_sha256;
	}

	kex_state initiate() override {
		return kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		return kex_state::error;
	}

	void set_crypto_configuration(crypto_configuration conf) override {
		conf_ = conf;
	}

private:
	kex_context context_;
	crypto_configuration conf_;
};

std::unique_ptr<kex> construct_kex(kex_type t, kex_context kex_c) {
	using enum kex_type;
	if(t == curve25519_sha256) {
		return std::make_unique<curve25519_sha256_kex>(kex_c);
	}
	return nullptr;
}

}

