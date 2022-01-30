#ifndef SP_SHH_TRANSPORT_HEADER
#define SP_SHH_TRANSPORT_HEADER

#include "packet_types.hpp"
#include "ssh_config.hpp"
#include "ssh_layer.hpp"
#include "stream_crypto.hpp"

#include <libfilezilla/logger.hpp>

namespace securepath::ssh {

class in_buffer;
class out_buffer;

enum class ssh_state {
	none,
	version_exchange,
	kex,
	disconnected
};

/** \brief SSH Version 2 transport layer
 */
class ssh_transport {
public:
	ssh_transport(ssh_config const&, out_buffer&, fz::logger_interface* logger = nullptr);

	layer_op handle(in_buffer&);

	void disconnect(std::uint32_t, std::string_view message = {});

	ssh_state state() const;
	void set_state(ssh_state);

protected:
	virtual void on_version_exchange(ssh_version const&);

private:
	layer_op handle_version_exchange(in_buffer& in);
	layer_op handle_binary_packet(in_buffer& in);
	layer_op handle_payload(in_buffer& in);

private:
	ssh_config const& config_;
	out_buffer& output_;
	fz::logger_interface* logger_;

	ssh_state state_{ssh_state::none};

	bool client_version_received_{};
	ssh_version client_version_;

	stream_in_crypto  crypto_in_;
	stream_out_crypto crypto_out_;

	// current kex
};

}

#endif
