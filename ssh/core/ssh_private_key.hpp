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
	ssh_private_key(std::shared_ptr<private_key>, std::string_view comment = "");

	key_type type() const;
	ssh_public_key public_key() const;

	bool valid() const;

	// this will return encoded ssh signature
	byte_vector sign(const_span in) const;

	bool serialise(binout&) const;

	void set_comment(std::string s) { comment_ = std::move(s); }
	std::string const& comment() const { return comment_; }

private:
	std::shared_ptr<private_key> key_impl_;
	std::string comment_;
};

// this just interprets raw bytes as the private key data in similar fashion as with ssh public key formats
ssh_private_key load_raw_ssh_private_key(const_span data, crypto_context const&, crypto_call_context const&);
ssh_private_key load_raw_base64_ssh_private_key(std::string_view data, crypto_context const&, crypto_call_context const&);

// try to load one of the supported formats (e.g. openssh private key format)
ssh_private_key load_ssh_private_key(const_span data, crypto_context const&, crypto_call_context const&);

byte_vector to_byte_vector(ssh_private_key const&);

// save private key as openssh new private key format
std::string save_openssh_private_key(ssh_private_key const&, crypto_context const&, crypto_call_context const&);

}

#endif
