#ifndef SP_SHH_CLIENT_AUTH_SERVICE_HEADER
#define SP_SHH_CLIENT_AUTH_SERVICE_HEADER

#include "ssh/core/service/ssh_service.hpp"

namespace securepath::ssh {

class client_auth_service : public ssh_service {
public:

	std::string_view name() const override;
	service_state state() const override;
	handler_result process(ssh_packet_type, const_span payload) override;

private:
	service_state state_{service_state::none};
};

}

#endif
