#ifndef SP_SHH_PACKET_SER_HEADER
#define SP_SHH_PACKET_SER_HEADER

#include "types.hpp"

namespace securepath::ssh::ser {

// type tags for packet serialisation
struct byte;
struct uint32;
struct string;
struct data;

template<ssh_packet_type, typename... TypeTags>
class ssh_packet_ser;

/*
   byte      SSH_MSG_DISCONNECT
   uint32    reason code
   string    description in ISO-10646 UTF-8 encoding [RFC3629]
   string    language tag [RFC3066]
*/
using disconnect = ssh_packet_ser
<
	ssh_disconnect
	uint32,
	string,
	string
>;

}

#endif
