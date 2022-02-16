#ifndef SP_SHH_TRANSPORT_HEADER
#define SP_SHH_TRANSPORT_HEADER

#include "logger.hpp"
#include "packet_types.hpp"
#include "ssh_config.hpp"
#include "ssh_layer.hpp"
#include "stream_crypto.hpp"

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
class ssh_transport {
public:
	ssh_transport(ssh_config const&, out_buffer&, logger&);

	layer_op handle(in_buffer&);

	void disconnect(std::uint32_t, std::string_view message = {});

	ssh_state state() const;
	void set_state(ssh_state);

	//get error

protected:
	virtual void on_version_exchange(ssh_version const&);
	virtual ??? handle_transport_payload(span payload);

private: // init & generic packet handling
	layer_op handle_version_exchange(in_buffer& in);
	layer_op handle_binary_packet(in_buffer& in);
	void set_error_and_disconnect(ssh_error_code);

private: // input
	bool set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac);
	bool try_decode_header(span in_data);
	span decrypt_packet(span in_data);
	span decrypt_aead(aead_cipher& cip, const_span data, span out);
	span decrypt_with_mac(const_span data, span out);

private: // output


private: // data
	ssh_config const& config_;
	out_buffer& output_;
	logger& logger_;

	ssh_state state_{ssh_state::none};
	ssh_error_code error_{};

	bool client_version_received_{};
	ssh_version client_version_;

	stream_in_crypto  crypto_in_;
	stream_out_crypto crypto_out_;

	// current kex
};

}

#endif
