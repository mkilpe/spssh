#ifndef SP_SHH_CONNECTION_PROTOCOL_HEADER
#define SP_SHH_CONNECTION_PROTOCOL_HEADER

#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_types.hpp"

namespace securepath::ssh::ser {

/*
	byte      SSH_MSG_GLOBAL_REQUEST
	string    request name in US-ASCII only
	boolean   want reply
 	....      request-specific data follows
*/
using global_request = ssh_packet_ser
<
	ssh_global_request,
	string,
	boolean
>;

/*
	byte     SSH_MSG_REQUEST_SUCCESS
	....     response specific data
*/
using request_success = ssh_packet_ser
<
	ssh_request_success
>;

/*
	byte     SSH_MSG_REQUEST_FAILURE
	....     response specific data
*/
using request_failure = ssh_packet_ser
<
	ssh_request_failure
>;

/*
	byte      SSH_MSG_CHANNEL_OPEN
	string    channel type in US-ASCII only
	uint32    sender channel
	uint32    initial window size
	uint32    maximum packet size
	....      channel type specific data follows
*/
using channel_open = ssh_packet_ser
<
	ssh_channel_open,
	string,
	uint32,
	uint32,
	uint32
>;

/*
	byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
	uint32    recipient channel
	uint32    sender channel
	uint32    initial window size
	uint32    maximum packet size
	....      channel type specific data follows
*/
using channel_open_confirmation = ssh_packet_ser
<
	ssh_channel_open_confirmation,
	uint32,
	uint32,
	uint32,
	uint32
>;

/*
	byte      SSH_MSG_CHANNEL_OPEN_FAILURE
	uint32    recipient channel
	uint32    reason code
	string    description in ISO-10646 UTF-8 encoding [RFC3629]
	string    language tag [RFC3066]
*/
using channel_open_failure = ssh_packet_ser
<
	ssh_channel_open_failure,
	uint32,
	uint32,
	string,
	string
>;

enum open_failure_reason : std::uint32_t {
	administratively_prohibited = 1,
    connect_failed              = 2,
    unknown_channel_type        = 3,
    resource_shortage           = 4
};

/*
	byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
	uint32    recipient channel
	uint32    bytes to add
*/
using channel_window_adjust = ssh_packet_ser
<
	ssh_channel_window_adjust,
	uint32,
	uint32
>;

/*
	byte      SSH_MSG_CHANNEL_DATA
	uint32    recipient channel
	string    data

*/
using channel_data = ssh_packet_ser
<
	ssh_channel_data,
	uint32,
	string
>;

/*
	byte      SSH_MSG_CHANNEL_EXTENDED_DATA
	uint32    recipient channel
	uint32    data_type_code
	string    data
*/
using channel_extended_data = ssh_packet_ser
<
	ssh_channel_extended_data,
	uint32,
	uint32,
	string
>;

enum extended_data_type : std::uint32_t {
	stderr = 1
};

/*
	byte      SSH_MSG_CHANNEL_EOF
	uint32    recipient channel
*/
using channel_eof = ssh_packet_ser
<
	ssh_channel_eof,
	uint32
>;

/*
	byte      SSH_MSG_CHANNEL_CLOSE
	uint32    recipient channel
*/
using channel_close = ssh_packet_ser
<
	ssh_channel_close,
	uint32
>;

}

#endif