#ifndef SP_SSH_CRYPTO_COMPRESSION_HEADER
#define SP_SSH_CRYPTO_COMPRESSION_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class compression {
public:
	virtual ~compression() = default;

	/// Process block of data (either compress or decompress)
	virtual bool process(span input, out_buffer&) = 0;
};

}

#endif
