#ifndef SP_SHH_TRANSPORT_HEADER
#define SP_SHH_TRANSPORT_HEADER

#include "logger.hpp"
#include "packet_types.hpp"
#include "ssh_config.hpp"
#include "ssh_layer.hpp"
#include "ssh_binary_packet.hpp"

namespace securepath::ssh {

class in_buffer;
class out_buffer;

enum class ssh_state {
	none,
	version_exchange,
	kex,
	transport,
	user_authentication,
	subsystem,
	disconnected
};

/** \brief SSH Version 2 transport layer
 */
class ssh_transport : private ssh_binary_packet {
public:
	ssh_transport(ssh_config const&, out_buffer&, logger&);

	layer_op handle(in_buffer&);

	void disconnect(std::uint32_t, std::string_view message = {});

	ssh_state state() const;
	void set_state(ssh_state);

	using ssh_binary_packet::error;
	using ssh_binary_packet::error_message;

protected:
	virtual void on_version_exchange(ssh_version const&);
	virtual bool handle_transport_payload(ssh_packet_type, const_span payload);

private: // init & generic packet handling
	layer_op handle_version_exchange(in_buffer& in);
	layer_op handle_binary_packet(in_buffer& in);
	void set_error_and_disconnect(ssh_error_code);

private: // input
	layer_op process_transport_payload(span payload);

private: // output
	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args);

private: // data
	out_buffer& output_;

	ssh_state state_{ssh_state::none};

	bool client_version_received_{};
	ssh_version client_version_;

	// current kex
};

}

#endif
