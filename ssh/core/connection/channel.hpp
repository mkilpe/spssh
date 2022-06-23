#ifndef SP_SHH_CHANNEL_HEADER
#define SP_SHH_CHANNEL_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

using channel_id = std::uint32_t;

class channel {
public:
	virtual ~channel() = default;

	// in and out:
	//   data
	//   extended data
	//   eof
	//   close

};

}

#endif
