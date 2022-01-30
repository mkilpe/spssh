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

	bool random_packet_padding{true};
};

}

#endif
