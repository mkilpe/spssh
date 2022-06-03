#ifndef SP_SHH_PUBLIC_KEY_HEADER
#define SP_SHH_PUBLIC_KEY_HEADER

#include "ssh/crypto/crypto_context.hpp"
#include "ssh/crypto/public_key.hpp"
#include <memory>

namespace securepath::ssh {

class binout;

/** \brief SSH Public Key that is used for signature checking
 */
class ssh_public_key {
public:
	ssh_public_key() = default;
	ssh_public_key(std::shared_ptr<public_key>);

	key_type type() const;
	bool valid() const;

	// signature needs to be ssh encoded signature
	bool verify(const_span msg, const_span signature) const;

	bool serialise(binout&) const;

	// sha256 fingerprint with base64 encoding
	std::string fingerprint(crypto_context const& crypto, crypto_call_context const& call) const;
private:
	std::shared_ptr<public_key> key_impl_;
};

ssh_public_key load_ssh_public_key(const_span data, crypto_context const&, crypto_call_context const&);
ssh_public_key load_base64_ssh_public_key(std::string_view data, crypto_context const&, crypto_call_context const&);

byte_vector to_byte_vector(ssh_public_key const&);

}

#endif
