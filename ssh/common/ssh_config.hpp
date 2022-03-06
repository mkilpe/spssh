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
	// re-key interval

	// add random size of padding for each packet
	bool random_packet_padding{true};

	// maximum output buffer size, single transport packet cannot be bigger than this
	std::size_t max_out_buffer_size{128*1024};

	// size to shrink the output buffer after handling output packet
	std::size_t shrink_out_buffer_size{std::size_t(-1)};

	// use in place operations for output buffer, this disables compression
	bool use_in_place_buffer{true};
};

}

#endif
