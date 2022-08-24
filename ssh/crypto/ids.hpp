#ifndef SP_SSH_CRYPTO_IDS_HEADER
#define SP_SSH_CRYPTO_IDS_HEADER

#include "ssh/common/algo_list.hpp"
#include <string_view>

namespace securepath::ssh {

enum class cipher_type {
	unknown = 0,
	aes_256_gcm,
	openssh_aes_256_gcm, // same as above but with different name
	aes_256_ctr
};

std::string_view to_string(cipher_type);
cipher_type from_string(type_tag<cipher_type>, std::string_view);

enum class cipher_dir {
	encrypt,
	decrypt
};

std::size_t cipher_iv_size(cipher_type);
std::size_t cipher_key_size(cipher_type);

enum class mac_type {
	unknown = 0,
	implicit,         // this should never be added to supported macs, it is just a place holder for openssh aead
	aes_256_gcm,
	hmac_sha2_256
};

std::string_view to_string(mac_type);
mac_type from_string(type_tag<mac_type>, std::string_view);

std::size_t mac_key_size(mac_type);

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

std::size_t const ed25519_key_size = 32;

std::string_view to_string(key_type);
key_type from_string(type_tag<key_type>, std::string_view);

// this will give the curve name only for ecdsa types, otherwise empty
std::string_view to_curve_name(key_type);

enum class key_exchange_type {
	unknown = 0,
	X25519,
	dh_group14,
	dh_group16
};

std::string_view to_string(key_exchange_type);
key_exchange_type from_string(type_tag<key_exchange_type>, std::string_view);

enum class hash_type {
	unknown = 0,
	sha2_256,
	sha2_512
};

std::string_view to_string(hash_type);
hash_type from_string(type_tag<hash_type>, std::string_view);

}

#endif
