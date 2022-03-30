#ifndef SP_SHH_PUBLIC_KEY_HEADER
#define SP_SHH_PUBLIC_KEY_HEADER

#include "ssh/crypto/crypto_context.hpp"
#include "ssh/crypto/public_key.hpp"
#include <memory>

namespace securepath::ssh {

/** \brief SSH Public Key that is used for signature checking
 */
class ssh_public_key {
public:
	ssh_public_key() = default;
	ssh_public_key(std::unique_ptr<public_key>);

	key_type type() const;
	bool valid() const;

	bool verify(const_span msg, const_span signature) const;

private:
	std::unique_ptr<public_key> key_impl_;
};

ssh_public_key load_ssh_public_key(const_span data, crypto_context const&, crypto_call_context const&);
ssh_public_key load_base64_ssh_public_key(std::string_view data, crypto_context const&, crypto_call_context const&);

}

#endif
