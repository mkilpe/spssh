#ifndef SP_SHH_TRANSPORT_HEADER
#define SP_SHH_TRANSPORT_HEADER

#include "packet_types.hpp"
#include "ssh_config.hpp"
#include "ssh_binary_packet.hpp"

#include "ssh/common/logger.hpp"
#include "ssh/crypto/crypto_context.hpp"

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

enum class transport_op {
	want_read_more,
	want_write_more,
	disconnected
};

class kex;

/** \brief SSH Version 2 transport layer
 */
class ssh_transport : private ssh_binary_packet {
public:
	ssh_transport(ssh_config const&, logger&, out_buffer&, crypto_context);
	~ssh_transport();

	/// This is the main driving function, reads from in_buffer and writes to out_buffer
	transport_op process(in_buffer&);

	void disconnect(std::uint32_t, std::string_view message = {});

	ssh_state state() const;
	void set_state(ssh_state, std::optional<ssh_error_code> = std::nullopt);

	out_buffer& output_buffer() { return output_; }

	using ssh_binary_packet::error;
	using ssh_binary_packet::error_message;

	void send_ignore(std::size_t size);

protected:
	virtual void on_version_exchange(ssh_version const&);
	virtual bool handle_basic_packets(ssh_packet_type, const_span payload);

protected:
	using ssh_binary_packet::config_;

private: // init & generic packet handling
	void set_error_and_disconnect(ssh_error_code);

	void handle_version_exchange(in_buffer& in);
	void handle_binary_packet(in_buffer& in);
	bool handle_kex_packet(ssh_packet_type type, const_span payload);
	bool handle_raw_kex_packet(ssh_packet_type type, const_span payload);
	bool handle_kexinit_packet(const_span payload);
	bool handle_kex_done();

	bool send_kex_init(bool send_first_packet);
	void send_kex_guess();

private: // input
	bool process_transport_payload(span payload);

private: // output
	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args);

private: // data
	crypto_context crypto_;
	out_buffer& output_;

	ssh_state state_{ssh_state::none};

	bool remote_version_received_{};

	std::unique_ptr<random> rand_;

	// kex data
	bool kexinit_received_{};
	byte_vector kex_cookie_;

	kex_init_data kex_data_;
	bool ignore_next_kex_packet_{};
	std::unique_ptr<kex> kex_;
};

}

#endif
