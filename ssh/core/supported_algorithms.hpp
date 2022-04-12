#ifndef SP_SUPPORTED_ALGORITHMS_HEADER
#define SP_SUPPORTED_ALGORITHMS_HEADER

#include "kexinit.hpp"

#include "ssh/common/algo_list.hpp"
#include "ssh/crypto/ids.hpp"

namespace securepath::ssh {

using kex_list = algo_list<kex_type>;
using key_list = algo_list<key_type>;
using cipher_list = algo_list<cipher_type>;
using mac_list = algo_list<mac_type>;
using compress_list = algo_list<compress_type>;

struct supported_algorithms {
	// supported kex
	kex_list kexes;

	// supported host key types
	key_list host_keys;

	// supported ciphers client->server
	cipher_list client_server_ciphers;
	// supported ciphers server->client
	cipher_list server_client_ciphers;

	// supported macs client->server
	mac_list client_server_macs;
	// supported macs server->client
	mac_list server_client_macs;

	// supported compression client->server
	compress_list client_server_compress{compress_type::none};
	// supported compression server->client
	compress_list server_client_compress{compress_type::none};

public:
	bool valid() const;

	void dump(std::string_view tag, logger&) const;
};

}

#endif
