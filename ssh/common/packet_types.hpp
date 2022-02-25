#ifndef SP_SHH_PACKET_TYPES_HEADER
#define SP_SHH_PACKET_TYPES_HEADER

#include "types.hpp"

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

enum ssh_error_code : std::uint32_t {
	ssh_noerror                        = 0,
	ssh_host_not_allowed_to_connect    = 1,
	ssh_protocol_error                 = 2,
	ssh_key_exchange_failed            = 3,
	ssh_reserved                       = 4,
	ssh_mac_error                      = 5,
	ssh_compression_error              = 6,
	ssh_service_not_available          = 7,
	ssh_protocol_version_not_supported = 8,
	ssh_host_key_not_verifiable        = 9,
	ssh_connection_lost                = 10,
	ssh_disconnect_by_application      = 11,
	ssh_too_many_connections           = 12,
	ssh_auth_cancelled_by_user         = 13,
	ssh_no_more_auth_methods_available = 14,
	ssh_illegal_user_name              = 15,

	//0x00000010-0xFDFFFFFF	Unassigned
	//0xFE000000-0xFFFFFFFF	Reserved for Private Use

	//spssh defined errors
	spssh_memory_error                 = 0xFFFF0001
};

}

#endif
