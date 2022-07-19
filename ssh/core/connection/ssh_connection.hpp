#ifndef SP_SHH_CONNECTION_HEADER
#define SP_SHH_CONNECTION_HEADER

#include "channel.hpp"
#include "ssh/core/service/ssh_service.hpp"

#include <functional>
#include <map>
#include <memory>

namespace securepath::ssh {

class transport_base;

using channel_constructor = std::function<std::unique_ptr<channel>(transport_base&, channel_side_info)>;

/// Implements the core of SSH connection protocol (RFC4254)
class ssh_connection : public ssh_service {
public:
	ssh_connection(transport_base&);

	// add channel type that can be used by the connection
	void add_channel_type(std::string_view type, channel_constructor ctor);

	// initiate open channel
	channel_base* open_channel(std::string_view type);

	// find channel
	channel_base* find_channel(channel_id) const;

	std::string_view name() const override;
	service_state state() const override;

	bool flush() override;

protected:
	bool init() override;
	handler_result process(ssh_packet_type, const_span payload) override;
	std::unique_ptr<channel_base> construct_channel(std::string_view type);
	void add_channel(std::unique_ptr<channel_base> ch);

protected:
	handler_result handle_open(const_span payload);
	handler_result handle_open_confirm(const_span payload);
	handler_result handle_open_failure(const_span payload);
	handler_result handle_close(const_span payload);
	handler_result handle_global_request(const_span payload);
	handler_result handle_request_success(const_span payload);
	handler_result handle_request_failure(const_span payload);
	handler_result handle_window_adjust(const_span payload);
	handler_result handle_data(const_span payload);
	handler_result handle_extended_data(const_span payload);
	handler_result handle_eof(const_span payload);

private:
	transport_base& transport_;
	logger& log_;
	ssh_config const& config_;
	service_state state_{service_state::inprogress};

	std::map<std::string, channel_constructor, std::less<>> channel_ctors_;
	std::map<channel_id, std::unique_ptr<channel_base>> channels_;

	channel_id current_id_{};
};

}

#endif
