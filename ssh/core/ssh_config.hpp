#ifndef SP_SHH_CONFIG_HEADER
#define SP_SHH_CONFIG_HEADER

#include "ssh_private_key.hpp"
#include "supported_algorithms.hpp"

namespace securepath::ssh {

struct key_pair {
	ssh_private_key key;
	byte_vector ser_pubkey;
};

/** \brief SSH Version 2 Configuration
 */
struct ssh_config {
	transport_side side{transport_side::client};

	// software name and version
	ssh_version my_version{.ssh="2.0"};

	// supported algorithms
	supported_algorithms algorithms;

	// host keys for server, possible authentication keys for client
	std::vector<key_pair> private_keys;

	// re-key interval in bytes (== 0 means no rekeying)
	std::uint64_t rekey_inverval{1024ULL*1024*1024*2};

	// add random size of padding for each packet
	bool random_packet_padding{true};

	// maximum output buffer size (should be at least max_out_packet_size)
	std::uint32_t max_out_buffer_size{128*1024};

	// size to shrink the output buffer after handling output packet
	std::uint32_t shrink_out_buffer_size{std::uint32_t(-1)};

	// the maximum size for incoming packet, the external buffer must be able to hold at least this many bytes
	std::uint32_t max_in_packet_size{64*1024};

	// the maximum size for outgoing packet, the external buffer must be able to hold at least this many bytes
	std::uint32_t max_out_packet_size{64*1024};

	// send initial guess of kex before receiving remote side kex-init packet
	bool guess_kex_packet{false};

public:
	// simple check that we have at least one kexes, cipher and so on (does not check if the algorithms are compatible)
	bool valid() const;

	// sets the private_keys and fills the host_keys to match it, if adding any of the key fails, none is set and false returned
	bool set_host_keys_for_server(std::vector<ssh_private_key> keys);

	// add single private key to the private_keys (does not change the supported algorithms)
	bool add_private_key(ssh_private_key);
};

}

#endif
