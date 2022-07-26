#ifndef SP_SHH_PACKET_TYPES_HEADER
#define SP_SHH_PACKET_TYPES_HEADER

#include "ssh/common/types.hpp"

#include <iosfwd>

namespace securepath::ssh {

enum ssh_packet_type : std::uint8_t {
	ssh_disconnect                = 1,
	ssh_ignore                    = 2,
	ssh_unimplemented             = 3,
	ssh_debug                     = 4,
	ssh_service_request           = 5,
	ssh_service_accept            = 6,
	ssh_ext_info                  = 7,
	ssh_newcompress               = 8,
	// 9-19		Unassigned (Transport layer generic)
	ssh_kexinit                   = 20,
	ssh_newkeys                   = 21,
	// 22-29	Unassigned (Algorithm negotiation)
	// 30-49	Reserved (key exchange method specific)
	ssh_userauth_request          = 50,
	ssh_userauth_failure          = 51,
	ssh_userauth_success          = 52,
	ssh_userauth_banner           = 53,
	// 54-59	Unassigned (User authentication generic)
	ssh_userauth_info_request     = 60,
	ssh_userauth_info_response    = 61,
	// 62-79	Reserved (User authentication method specific)
	ssh_global_request            = 80,
	ssh_request_success           = 81,
	ssh_request_failure           = 82,
	// 83-89	Unassigned (Connection protocol generic)
	ssh_channel_open              = 90,
	ssh_channel_open_confirmation = 91,
	ssh_channel_open_failure      = 92,
	ssh_channel_window_adjust     = 93,
	ssh_channel_data              = 94,
	ssh_channel_extended_data     = 95,
	ssh_channel_eof               = 96,
	ssh_channel_close             = 97,
	ssh_channel_request           = 98,
	ssh_channel_success           = 99,
	ssh_channel_failure           = 100,
	// 101-127	Unassigned (Channel related messages)
	// 128-191	Reserved (for client protocols)
	// 192-255	Reserved for Private Use (local extensions)
};

bool is_kex_packet(ssh_packet_type);

std::ostream& operator<<(std::ostream&, ssh_packet_type);

}

#endif
