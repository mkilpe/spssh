#ifndef SP_SHH_PRIVATE_KEY_HEADER
#define SP_SHH_PRIVATE_KEY_HEADER

#include "ssh_public_key.hpp"
#include "ssh/crypto/crypto_context.hpp"
#include "ssh/crypto/private_key.hpp"
#include <memory>

namespace securepath::ssh {

/** \brief SSH Private Key that is used for Client authentication and Server host key
 */
class ssh_private_key {
public:
	ssh_private_key() = default;
	ssh_private_key(std::unique_ptr<private_key>, std::string_view comment = "");

	key_type type() const;
	ssh_public_key public_key() const;

	bool valid() const;

	std::size_t signature_size() const;
	void sign(const_span in, span out) const;
	byte_vector sign(const_span in) const;

private:
	std::unique_ptr<private_key> key_impl_;
	std::string comment_;
};

// this just interprets raw bytes as the private key data in similar fashion as with ssh public key formats
ssh_private_key load_raw_ssh_private_key(const_span data, crypto_context const&, crypto_call_context const&);
ssh_private_key load_raw_base64_ssh_private_key(std::string_view data, crypto_context const&, crypto_call_context const&);

//todo: add function to load real formats like openssh private key

}

#endif
