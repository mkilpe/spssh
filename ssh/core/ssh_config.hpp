#ifndef SP_SHH_CONFIG_HEADER
#define SP_SHH_CONFIG_HEADER

#include "ssh_private_key.hpp"
#include "supported_algorithms.hpp"

namespace securepath::ssh {

/** \brief SSH Version 2 Configuration
 */
struct ssh_config {
	transport_side side{transport_side::client};

	// software name and version
	ssh_version my_version{.ssh="2.0"};

	// supported algorithms
	supported_algorithms algorithms;

	// host keys for server, possible authentication keys for client
	std::vector<ssh_private_key> private_keys;

	// re-key interval in bytes (== 0 means no rekeying)
	std::uint64_t rekey_inverval{1024ULL*1024*1024*2};

	// add random size of padding for each packet
	bool random_packet_padding{true};

	// maximum output buffer size, single transport packet cannot be bigger than this
	std::size_t max_out_buffer_size{128*1024};

	// size to shrink the output buffer after handling output packet
	std::size_t shrink_out_buffer_size{std::size_t(-1)};

	// send initial guess of kex before receiving remote side kex-init packet
	bool guess_kex_packet{false};

public:
	// simple check that we have at least one kexes, cipher and so on (does not check if the algorithms are compatible)
	bool valid() const;

	// sets the private_keys and fills the host_keys to match it
	void set_host_keys_for_server(std::vector<ssh_private_key> keys);
};

}

#endif
