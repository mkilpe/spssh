#ifndef SP_SHH_KEXINIT_HEADER
#define SP_SHH_KEXINIT_HEADER

#include "errors.hpp"
#include "ssh/crypto/ids.hpp"

#include <iosfwd>
#include <optional>
#include <string_view>

namespace securepath::ssh {

enum class kex_type {
	unknown = 0,
	dh_group14_sha256,
	curve25519_sha256,
	ecdh_sha2_nistp256
};

std::string_view to_string(kex_type);
kex_type from_string(type_tag<kex_type>, std::string_view);

struct crypto_configuration {
	kex_type kex{};
	key_type host_key{};

	struct type {
		cipher_type cipher{};
		mac_type mac{};
		compress_type compress{};

		friend bool operator==(type const&, type const&) = default;
	} in, out;

	friend bool operator==(crypto_configuration const&, crypto_configuration const&) = default;
};

std::ostream& operator<<(std::ostream&, crypto_configuration const&);

class supported_algorithms;
class logger;

class kexinit_agreement {
public:
	kexinit_agreement(logger&, transport_side my_side, supported_algorithms const& my);

	bool agree(supported_algorithms const& remote);
	bool was_guess_correct() const;

	crypto_configuration agreed_configuration() const;

private:
	logger& logger_;
	transport_side my_side_;
	supported_algorithms const& my_;
	std::optional<crypto_configuration> agreed_;
	bool guess_was_correct_{};
};

}

#endif
