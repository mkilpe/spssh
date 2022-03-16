#ifndef SP_SHH_CONFIG_HEADER
#define SP_SHH_CONFIG_HEADER

#include "ssh_private_key.hpp"
#include "kex.hpp"

#include "ssh/common/types.hpp"
#include "ssh/common/algo_list.hpp"
#include "ssh/crypto/ids.hpp"

namespace securepath::ssh {

using kex_list = algo_list<kex_type>;
using cipher_list = algo_list<cipher_type>;
using mac_list = algo_list<mac_type>;
using compress_list = algo_list<compress_type>;

/** \brief SSH Version 2 Configuration
 */
struct ssh_config {

	// software name and version
	ssh_version my_version{.ssh="2.0"};

	// host keys
	std::vector<ssh_private_key> host_keys;

	// supported kex
	kex_list kexes;

	// supported ciphers client->server
	cipher_list client_server_ciphers;
	// supported ciphers server->client
	cipher_list server_client_ciphers;

	// supported macs client->server
	mac_list client_server_macs;
	// supported macs server->client
	mac_list server_client_macs;

	// supported compression client->server
	compress_list client_server_compress;
	// supported compression server->client
	compress_list server_client_compress;

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
	std::vector<std::string_view> host_key_list() const;
};

}

#endif
