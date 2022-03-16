#ifndef SP_SSH_CRYPTO_IDS_HEADER
#define SP_SSH_CRYPTO_IDS_HEADER

#include <string_view>

namespace securepath::ssh {

enum class cipher_type {
	unknown = 0,
	aes_256_gcm,
	aes_256_ctr
};

std::string_view to_string(cipher_type);
cipher_type cipher_type_from_string(std::string_view);

enum class mac_type {
	unknown = 0,
	aes_256_gcm,
	hmac_sha2_256
};

std::string_view to_string(mac_type);
mac_type mac_type_from_string(std::string_view);

// nothing supported for now
enum class compress_type {
	unknown = 0,
	none
};

std::string_view to_string(compress_type);
compress_type compress_type_from_string(std::string_view);

enum class key_type {
	unknown = 0,
	ssh_rsa,
	ssh_ed25519,
	ecdsa_sha2_nistp256
};

std::string_view to_string(key_type);
key_type key_type_from_string(std::string_view);

}

#endif
