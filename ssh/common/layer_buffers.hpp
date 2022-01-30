#ifndef SP_SSH_LAYER_BUFFERS_HEADER
#define SP_SSH_LAYER_BUFFERS_HEADER

#include "types.hpp"

namespace securepath::ssh {

/** \brief Buffer interface for output in the SSH layers
 *
 *
 */
class out_layer_buffer {
protected:
	~out_layer_buffer() = default;
public:
	/// Get continuous range to write output packet. Returns span with at least size bytes.
	virtual span get(std::size_t size) = 0;

	/// Commit to the size of the output packet after writing to above span. Size given must be less or equal to the size of the span.
	virtual void commit(std::uint32_t packet_type, std::size_t size) = 0;
};

}

#endif
