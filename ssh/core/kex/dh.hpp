#ifndef SPSSH_CORE_KEX_DH_HEADER
#define SPSSH_CORE_KEX_DH_HEADER

#include "ssh/core/packet_ser.hpp"

namespace securepath::ssh {

enum dh_packet_type : std::uint8_t {
	ssh_kexdh_init = 30,
	ssh_kexdh_reply = 31
};

namespace ser {

/*
      byte     SSH_MSG_KEX_ECDH_INIT
      mpint    e = g^x mod p, where p is a large safe prime; g is a generator
	         for a subgroup of GF(p); q is the order of the subgroup
*/
using kexdh_init = ssh_packet_ser
<
	ssh_kexdh_init,
	mpint
>;

/*
      byte     SSH_MSG_KEX_ECDH_REPLY
	string   server public host key and certificates (K_S)
	mpint    f = g^y mod p, where y is random number (0 < y < q)
	string   signature of the exchange hash
*/
using kexdh_reply = ssh_packet_ser
<
	ssh_kexdh_reply,
	string,
	mpint,
	string
>;

}
}

#endif