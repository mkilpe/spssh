#ifndef SP_SSH_CRYPTO_COMPRESS_HEADER
#define SP_SSH_CRYPTO_COMPRESS_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class compress {
public:
	virtual ~compress() = default;

	/// Process block of data (either compress or decompress)
	virtual bool process(const_span in, span out) = 0;
};

}

#endif
