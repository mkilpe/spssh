#ifndef SP_SHH_CONFIG_HEADER
#define SP_SHH_CONFIG_HEADER

#include "types.hpp"

namespace securepath::ssh {

/** \brief SSH Version 2 Server Side Configuration
 */
struct ssh_config {

	ssh_version my_version{.ssh="2.0"};
	// software name and version
	// host keys
	// supported kex
	// supported ciphers/macs
	// supported compression
	// max packet size
	// re-key interval

	// add random size of padding for each packet
	bool random_packet_padding{true};

	// maximum output buffer size, single transport packet cannot be bigger than this
	std::size_t max_out_buffer_size{128*1024};

	// minimum output buffer size, this is the size allocated at the beginning and shrinked to
	std::size_t min_out_buffer_size{16*1024};

	// should we force shrinking of the output buffer after each packet
	bool always_shrink_out_buffer{};
};

}

#endif
