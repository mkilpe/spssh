#ifndef SP_SSH_CRYPTO_IDS_HEADER
#define SP_SSH_CRYPTO_IDS_HEADER

#include "ssh/common/algo_list.hpp"
#include <string_view>

namespace securepath::ssh {

enum class cipher_type {
	unknown = 0,
	aes_256_gcm,
	aes_256_ctr
};

std::string_view to_string(cipher_type);
cipher_type from_string(type_tag<cipher_type>, std::string_view);

enum class mac_type {
	unknown = 0,
	aes_256_gcm,
	hmac_sha2_256
};

std::string_view to_string(mac_type);
mac_type from_string(type_tag<mac_type>, std::string_view);

// nothing supported for now
enum class compress_type {
	unknown = 0,
	none
};

std::string_view to_string(compress_type);
compress_type from_string(type_tag<compress_type>, std::string_view);

enum class key_type {
	unknown = 0,
	ssh_rsa,
	ssh_ed25519,
	ecdsa_sha2_nistp256,
	end_of_list
};

enum key_capability {
	no_capability = 0,
	encryption_capable = 1,
	signature_capable = 2,
	both_capable = encryption_capable | signature_capable
};

key_capability constexpr key_capabilities[] {
	no_capability,
	both_capable,
	signature_capable,
	signature_capable
};

static_assert(sizeof(key_capabilities)/sizeof(key_capability) == std::size_t(key_type::end_of_list));

std::string_view to_string(key_type);
key_type from_string(type_tag<key_type>, std::string_view);

enum class key_exchange_type {
	unknown = 0,
	X25519
};

}

#endif
