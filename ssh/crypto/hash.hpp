#ifndef SP_SSH_CRYPTO_HASH_HEADER
#define SP_SSH_CRYPTO_HASH_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class hash {
public:
	hash(std::size_t size)
	: size_(size)
	{}

	virtual ~hash() = default;

	/// size of the hash digest in bytes
	std::size_t size() const { return size_; }

	/// feed data to calculate hash
	virtual void process(const_span in) = 0;

	/// output digest, this will reset the hash state
	virtual void digest(span out) = 0;

	byte_vector digest() {
		byte_vector ret;
		ret.resize(size());
		digest(ret);
		return ret;
	}

private:
	std::size_t const size_;
};

}

#endif
