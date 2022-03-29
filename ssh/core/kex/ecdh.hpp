#ifndef SPSSH_CORE_KEX_ECDH_HEADER
#define SPSSH_CORE_KEX_ECDH_HEADER

#include "ssh/core/packet_ser.hpp"

namespace securepath::ssh {

enum ecdh_packet_type : std::uint8_t {
	ssh_kex_ecdh_init = 30,
	ssh_kex_ecdh_reply = 31
};

namespace ser {

/*
      byte     SSH_MSG_KEX_ECDH_INIT
      string   Q_C, client's ephemeral public key octet string
*/
using kex_ecdh_init = ssh_packet_ser
<
	ssh_kex_ecdh_init,
	string
>;

/*
      byte     SSH_MSG_KEX_ECDH_REPLY
      string   K_S, server's public host key
      string   Q_S, server's ephemeral public key octet string
      string   the signature on the exchange hash
*/
using kex_ecdh_reply = ssh_packet_ser
<
	ssh_kex_ecdh_reply,
	string,
	string,
	string
>;

}
}

#endif