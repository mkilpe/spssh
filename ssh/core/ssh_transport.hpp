#ifndef SP_SHH_TRANSPORT_HEADER
#define SP_SHH_TRANSPORT_HEADER

#include "packet_types.hpp"
#include "ssh_config.hpp"
#include "ssh_layer.hpp"
#include "ssh_binary_packet.hpp"

#include "ssh/common/logger.hpp"

#include <iosfwd>

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
	disconnected,
};
std::string_view to_string(ssh_state);
std::ostream& operator<<(std::ostream&, ssh_state);

/** \brief SSH Version 2 transport layer
 */
class ssh_transport : private ssh_binary_packet {
public:
	ssh_transport(ssh_config const&, out_buffer&, logger&);

	layer_op handle(in_buffer&);

	void disconnect(std::uint32_t, std::string_view message = {});

	ssh_state state() const;
	void set_state(ssh_state);

	out_buffer& output_buffer() { return output_; }

	using ssh_binary_packet::error;
	using ssh_binary_packet::error_message;

protected:
	virtual void on_version_exchange(ssh_version const&);
	virtual bool handle_transport_payload(ssh_packet_type, const_span payload);

protected:
	using ssh_binary_packet::config_;

private: // init & generic packet handling
	void set_error_and_disconnect(ssh_error_code);

	layer_op handle_version_exchange(in_buffer& in);
	layer_op handle_binary_packet(in_buffer& in);
	layer_op handle_kex_packet(ssh_packet_type type, const_span payload);
	layer_op handle_kexinit_packet(const_span payload);

	bool send_kex_init(bool send_first_packet);
	void send_kex_guess();

private: // input
	layer_op process_transport_payload(span payload);

private: // output
	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args);

private: // data
	out_buffer& output_;

	ssh_state state_{ssh_state::none};

	bool remote_version_received_{};
	ssh_version remote_version_;

	// kex data
	bool kexinit_sent_{};
	bool kexinit_received_{};
	std::vector<std::byte> kex_cookie_;

	kex_init_data kex_data_;

	std::unique_ptr<kex> kex_;
};

}

#endif
