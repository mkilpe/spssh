#ifndef SP_SHH_PACKET_SER_HEADER
#define SP_SHH_PACKET_SER_HEADER

#include "packet_types.hpp"

namespace securepath::ssh::ser {

// type tags for packet serialisation
struct boolean;
struct byte;
struct uint32;
struct uint64;
struct mpint;
struct string;
struct string_list;
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
	ssh_disconnect,
	uint32,
	string,
	string
>;

/*
	byte      SSH_MSG_IGNORE
	string    data
*/
using ignore = ssh_packet_ser
<
	ssh_ignore,
	string
>;

/*
	byte      SSH_MSG_DEBUG
	boolean   always_display
	string    message in ISO-10646 UTF-8 encoding [RFC3629]
	string    language tag [RFC3066]
*/
using debug = ssh_packet_ser
<
	ssh_debug,
	boolean,
	string,
	string
>;

}

#endif
