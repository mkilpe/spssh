#ifndef SP_SSH_CRYPTO_CIPHER_HEADER
#define SP_SSH_CRYPTO_CIPHER_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class cipher {
public:
	cipher(std::size_t bsize, bool aead)
	: block_size_(bsize)
	, aead_(aead)
	{}

	virtual ~cipher() = default;

	/// cipher block size in bytes
	std::size_t block_size() const { return block_size_; }

	/// true if this is authenticated encryption with associated data (AEAD).
	bool is_aead() const { return aead_; }

	/// encrypt/decrypt, it is possible that the range in == out
	virtual bool process(const_span in, span out) = 0;

private:
	std::size_t const block_size_;
	bool const aead_;
};

class aead_cipher : public cipher {
public:
	aead_cipher(std::size_t bsize, std::size_t tag_size)
	: cipher(bsize, true)
	, tag_size_(tag_size)
	{}

	/// size of the authentication tag in bytes
	std::size_t tag_size() const { return tag_size_; }

	/// Process associated data that is authenticated
	virtual void process_auth(const_span in) = 0;

	/// output tag and reset the tag accumulation
	virtual void tag(span out) = 0;

private:
	std::size_t const tag_size_;
};

}

#endif
