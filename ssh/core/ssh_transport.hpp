#ifndef SP_SHH_TRANSPORT_HEADER
#define SP_SHH_TRANSPORT_HEADER

#include "packet_types.hpp"
#include "ssh_config.hpp"
#include "ssh_binary_packet.hpp"
#include "ssh_state.hpp"

#include "ssh/common/logger.hpp"
#include "ssh/crypto/crypto_context.hpp"

#include <iosfwd>

namespace securepath::ssh {

class in_buffer;
class out_buffer;

enum class transport_op {
	want_read_more,
	want_write_more,
	pending_action, // we are waiting for some action that is async (e.g. asking user about host key)
	disconnected
};

class kex;

/** \brief SSH Version 2 transport layer
 */
class ssh_transport : public transport_base, private ssh_binary_packet {
public:
	ssh_transport(ssh_config const&, logger&, out_buffer&, crypto_context);
	~ssh_transport();

	/// This is the main driving function, reads from in_buffer and writes to out_buffer
	transport_op process(in_buffer&);

	void disconnect(std::uint32_t = ssh_noerror, std::string_view message = {});

	ssh_state state() const;
	void set_state(ssh_state, std::optional<ssh_error_code> = std::nullopt);

	out_buffer& output_buffer() { return output_; }

	void send_ignore(std::size_t size);

	crypto_context const& crypto() const final { return crypto_; }
	crypto_call_context call_context() const final { return crypto_call_context{logger_, *rand_}; }

	const_span session_id() const override;

	void set_error_and_disconnect(ssh_error_code, std::string_view message = {}) override;
	ssh_config const& config() const final { return config_; }
	ssh_error_code error() const final { return ssh_binary_packet::error(); }
	std::string error_message() const final { return ssh_binary_packet::error_message(); }
	void set_error(ssh_error_code code, std::string_view message = {}) override;

protected:
	virtual void on_version_exchange(ssh_version const&);
	virtual bool handle_basic_packets(ssh_packet_type, const_span payload);
	virtual handler_result handle_kex_done(kex const&);
	virtual handler_result handle_transport_packet(ssh_packet_type, const_span payload) = 0;
	virtual void on_state_change(ssh_state, ssh_state) {}
	virtual bool flush() { return false; }

	std::optional<out_packet_record> alloc_out_packet(std::size_t data_size) override;
	bool write_alloced_out_packet(out_packet_record const&) override;
	std::uint32_t max_in_packet_size() override;
	std::uint32_t max_out_packet_size() override;
protected:
	using ssh_binary_packet::config_;
	using ssh_binary_packet::logger_;

private: // init & generic packet handling

	void handle_version_exchange(in_buffer& in);
	handler_result handle_binary_packet(in_buffer& in);
	bool handle_kex_packet(ssh_packet_type type, const_span payload);
	bool handle_raw_kex_packet(ssh_packet_type type, const_span payload);
	bool handle_kexinit_packet(const_span payload);
	bool handle_remote_newkeys();
	void kex_set_done();

	bool send_kex_init(bool send_first_packet);
	void send_kex_guess();

private: // input
	handler_result process_transport_payload(span payload);

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
	bool local_kex_done_{};
	bool remote_kex_done_{};
	std::unique_ptr<kex> kex_;

	bool flush_service_{};
};

}

#endif
