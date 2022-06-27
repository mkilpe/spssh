#ifndef SP_SHH_KEX_HEADER
#define SP_SHH_KEX_HEADER

#include "kexinit.hpp"
#include "packet_types.hpp"
#include "transport_base.hpp"
#include "ssh/crypto/crypto_context.hpp"

namespace securepath::ssh {

enum class kex_state {
	none,
	inprogress,
	succeeded,
	error
};

struct crypto_pair {
	std::unique_ptr<ssh::cipher> cipher;
	std::unique_ptr<ssh::mac> mac;
};

class kex {
public:
	virtual ~kex() = default;

	virtual kex_type type() const = 0;
	virtual kex_state state() const = 0;

	// notice that this is called before the crypto configuration is set
	virtual kex_state initiate() = 0;
	virtual kex_state handle(ssh_packet_type type, const_span payload) = 0;

	virtual void set_crypto_configuration(crypto_configuration conf) = 0;

	virtual std::optional<crypto_pair> construct_in_crypto_pair() = 0;
	virtual std::optional<crypto_pair> construct_out_crypto_pair() = 0;
	virtual const_span session_id() const = 0;
	virtual ssh_public_key server_host_key() const = 0;

	ssh_error_code error() const {
		return error_;
	}

	std::string error_message() const {
		return err_message_;
	}

protected:
	ssh_error_code error_{ssh_noerror};
	std::string err_message_;
};

class supported_algorithms;

class kex_context {
public:
	kex_context(transport_base& transport, kex_init_data const& init_data)
	: transport_(transport)
	, init_data_(init_data)
	{}

	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args) {
		logger().log(logger::debug_trace, "SSH kex sending packet [type={}]", int(Packet::packet_type));
		return transport_.send_packet<Packet>(std::forward<Args>(args)...);
	}

	ssh_config const& config() const { return transport_.config(); }
	kex_init_data const& init_data() const { return init_data_; }
	crypto_context const& ccontext() const { return transport_.crypto(); }
	crypto_call_context call_context() const { return transport_.call_context(); }
	ssh::logger& logger() const { return transport_.log(); }

private:
	transport_base& transport_;
	kex_init_data const& init_data_;
};

std::unique_ptr<kex> construct_kex(transport_side, kex_type, kex_context);

}

#endif
