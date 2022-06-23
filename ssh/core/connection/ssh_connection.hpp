#ifndef SP_SHH_CONNECTION_HEADER
#define SP_SHH_CONNECTION_HEADER

#include "channel.hpp"
#include "ssh/core/service/ssh_service.hpp"

#include <functional>
#include <map>
#include <memory>

namespace securepath::ssh {

class ssh_transport;

using channel_constructor = std::function<std::unique_ptr<channel>()>;

/// Implements the core of SSH connection protocol (RFC4254)
class ssh_connection : public ssh_service {
public:
	ssh_connection(ssh_transport&);

	std::string_view name() const override;
	service_state state() const override;

	bool init() override;

	handler_result process(ssh_packet_type, const_span payload) override;

private:
	ssh_transport& transport_;
	service_state state_{service_state::inprogress};

	std::map<std::string, channel_constructor> channel_ctors_;
	std::map<channel_id, std::unique_ptr<channel>> channels_;
};

}

#endif
