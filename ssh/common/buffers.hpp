#ifndef SP_SSH_BUFFERS_HEADER
#define SP_SSH_BUFFERS_HEADER

#include "types.hpp"

namespace securepath::ssh {

/** \brief Buffer interface for input
 *
 *
 */
class in_buffer {
protected:
	~in_buffer() = default;
public:
	/// Returns span representing the currently available bytes in buffer for reading
	virtual span get() = 0;

	/** \brief Consumes bytes that were used from the above returned span.
	 *   Size given must be less or equal to the size of the span.
	 *   Can be called multiple times as long as the total size together is less or equal to the span size
	 *   This does not invalidate the range returned by get, unless the whole range has been consumed
	 */
	virtual void consume(std::size_t size) = 0;
};

/** \brief Buffer interface for output
 *
 *
 */
class out_buffer {
protected:
	~out_buffer() = default;
public:
	/// Get continuous range to write output data. Returns span with at least size bytes or empty span if not possible.
	virtual span get(std::size_t size) = 0;

	/// Expand range acquired with get, if re-allocation is required, the 'used' bytes of data from previous range is copied to the new range.
	virtual span expand(std::size_t new_size, std::size_t used) = 0;

	/// Commit to the size of the output data after writing to above span. Size given must be less or equal to the size of the span.
	virtual void commit(std::size_t size) = 0;

	/// Maximum range the get can return (for example if it is limited by maximum buffer size)
	virtual std::size_t max_size() const = 0;

	/// Uses get and commit to write string_view to the buffer
	bool write(std::string_view);
};

}

#endif
