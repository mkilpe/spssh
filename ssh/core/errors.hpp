#ifndef SP_SHH_ERRORS_HEADER
#define SP_SHH_ERRORS_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

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
	spssh_invalid_setup                = 0xFFFF0001,
	spssh_memory_error                 = 0xFFFF0002,
	spssh_invalid_packet               = 0xFFFF0003,
	spssh_crypto_error                 = 0xFFFF0004,
	spssh_invalid_data                 = 0xFFFF0005
};

}

#endif
