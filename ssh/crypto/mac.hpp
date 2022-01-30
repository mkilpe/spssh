#ifndef SP_SSH_CRYPTO_MAC_HEADER
#define SP_SSH_CRYPTO_MAC_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class mac {
public:
	mac(std::size_t size)
	: size_(bsize)
	{}

	virtual ~mac() = default;

	/// size of the message authentication code in bytes
	std::size_t size() const { return size_; }

	/// feed data to calculate message authentication code
	virtual void process(const_span in) = 0;

	/// output mac and reset the mac accumulation
	virtual void result(span out) = 0;

private:
	std::size_t const size_;
};



}

#endif
