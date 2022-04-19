#ifndef SP_SHH_PROTOCOL_HEADER
#define SP_SHH_PROTOCOL_HEADER

#include "packet_ser.hpp"

namespace securepath::ssh::ser {

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

/*
	byte      SSH_MSG_UNIMPLEMENTED
	uint32    packet sequence number of rejected message
*/
using unimplemented = ssh_packet_ser
<
	ssh_unimplemented,
	uint32
>;

/*
	byte         SSH_MSG_KEXINIT
	byte[16]     cookie (random bytes)
	name-list    kex_algorithms
	name-list    server_host_key_algorithms
	name-list    encryption_algorithms_client_to_server
	name-list    encryption_algorithms_server_to_client
	name-list    mac_algorithms_client_to_server
	name-list    mac_algorithms_server_to_client
	name-list    compression_algorithms_client_to_server
	name-list    compression_algorithms_server_to_client
	name-list    languages_client_to_server
	name-list    languages_server_to_client
	boolean      first_kex_packet_follows
	uint32       0 (reserved for future extension)
*/
using kexinit = ssh_packet_ser
<
	ssh_kexinit,
	bytes<16>,
	name_list,
	name_list,
	name_list,
	name_list,
	name_list,
	name_list,
	name_list,
	name_list,
	name_list,
	name_list,
	boolean,
	uint32
>;

/*
	byte         SSH_MSG_NEWKEYS
*/
using newkeys = ssh_packet_ser
<
	ssh_newkeys
>;

/*
	byte      SSH_MSG_SERVICE_REQUEST
	string    service name
*/
using service_request = ssh_packet_ser
<
	ssh_service_request,
	string
>;

/*
	byte      SSH_MSG_SERVICE_ACCEPT
	string    service name
*/
using service_accept = ssh_packet_ser
<
	ssh_service_accept,
	string
>;

}

#endif
