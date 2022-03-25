#include "kex.hpp"
#include "ssh_config.hpp"

#include <ostream>

namespace securepath::ssh {

std::string_view to_string(kex_type t) {
	using enum kex_type;
	if(t == dh_group14_sha256) return "diffie-hellman-group14-sha256";
	if(t == curve25519_sha256) return "curve25519-sha256";
	if(t == ecdh_sha2_nistp256) return "ecdh-sha2-nistp256";
	return "unknown";
}

kex_type from_string(type_tag<kex_type>, std::string_view s) {
	using enum kex_type;
	if(s == "diffie-hellman-group14-sha256") return dh_group14_sha256;
	if(s == "curve25519-sha256") return curve25519_sha256;
	if(s == "ecdh-sha2-nistp256") return ecdh_sha2_nistp256;
	return unknown;
}

std::ostream& operator<<(std::ostream& out, crypto_configuration const& c) {
	return out << "kex=" << to_string(c.kex) << " host_key=" << to_string(c.host_key)
		<< " in={cipher=" << to_string(c.in.cipher) << " mac=" << to_string(c.in.mac) << " compress=" << to_string(c.in.compress)
		<< "} out={cipher=" << to_string(c.out.cipher) << " mac=" << to_string(c.out.mac) << " compress=" << to_string(c.out.compress)
		<< "}";
}

static bool is_compatible(kex_type kex, key_type key) {
	using enum kex_type;
	if(kex == curve25519_sha256) {
		return key_capabilities[std::size_t(key)] & signature_capable;
	}
	if(kex == dh_group14_sha256) {
		return key_capabilities[std::size_t(key)] & signature_capable;
	}
	if(kex == ecdh_sha2_nistp256) {
		return key_capabilities[std::size_t(key)] & signature_capable;
	}

	return false;
}

std::optional<crypto_configuration> crypto_config_guess(supported_algorithms const& c, transport_side side) {
	crypto_configuration guess;

	if(!c.valid()) {
		return std::nullopt;
	}

	guess.kex = c.kexes.preferred();
	for(auto&& hkey : c.host_keys) {
		if(is_compatible(guess.kex, hkey)) {
			guess.host_key = hkey;
			break;
		}
	}
	if(guess.host_key == key_type::unknown) {
		return std::nullopt;
	}

	// as seen from client side
	guess.in.cipher = c.server_client_ciphers.preferred();
	guess.out.cipher = c.client_server_ciphers.preferred();

	guess.in.mac = c.server_client_macs.preferred();
	guess.out.mac = c.client_server_macs.preferred();

	if(guess.in.cipher == cipher_type::aes_256_gcm && guess.in.mac != mac_type::aes_256_gcm) {
		return std::nullopt;
	}
	if(guess.out.cipher == cipher_type::aes_256_gcm && guess.out.mac != mac_type::aes_256_gcm) {
		return std::nullopt;
	}

	guess.in.compress = c.server_client_compress.preferred();
	guess.out.compress = c.client_server_compress.preferred();

	// if we are server, swap the values
	if(side == transport_side::server) {
		std::swap(guess.in.cipher, guess.out.cipher);
		std::swap(guess.in.mac, guess.out.mac);
		std::swap(guess.in.compress, guess.out.compress);
	}

	return guess;
}

struct curve25519_sha256_kex : public kex {
	curve25519_sha256_kex(kex_context kex_c)
	: context_(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex [{}]", context_.crypto_config());
	}

	crypto_configuration crypto_config() const override {
		return context_.crypto_config();
	}

	kex_state initiate() override {
		return kex_state::error;
	}

private:
	kex_context context_;
};

std::unique_ptr<kex> construct_kex(kex_context kex_c) {
	using enum kex_type;
	if(kex_c.crypto_config().kex == curve25519_sha256) {
		return std::make_unique<curve25519_sha256_kex>(kex_c);
	}
	return nullptr;
}

}

