#ifndef SP_SHH_KEX_HEADER
#define SP_SHH_KEX_HEADER

#include "kexinit.hpp"
#include "packet_types.hpp"
#include "ssh/crypto/crypto_context.hpp"

#include <optional>
#include <vector>

namespace securepath::ssh {

enum class kex_state {
	none,
	inprogress,
	succeeded,
	error
};

class kex {
public:
	virtual ~kex() = default;

	virtual kex_type type() const = 0;

	// notice that this is called before the crypto configuration is set
	virtual kex_state initiate() = 0;
	virtual kex_state handle(ssh_packet_type type, const_span payload) = 0;

	virtual void set_crypto_configuration(crypto_configuration conf) = 0;

	ssh_error_code error() const {
		return error_;
	}

	std::string error_message() const {
		return err_message_;
	}

protected:
	ssh_error_code error_;
	std::string err_message_;
};

class ssh_config;
class supported_algorithms;

struct kex_init_data {
	ssh_version local_ver;
	ssh_version remote_ver;
	std::vector<std::byte> local_kexinit;
	std::vector<std::byte> remote_kexinit;
};

class ssh_binary_packet;
class out_buffer;

class kex_context {
public:
	kex_context(ssh_config const& config, ssh_binary_packet& bpacket, out_buffer& output, kex_init_data const& init_data
		, crypto_context const& ccontext, crypto_call_context call_context)
	: config_(config)
	, bpacket_(bpacket)
	, output_(output)
	, init_data_(init_data)
	, ccontext_(ccontext)
	, call_context_(call_context)
	{}

	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args) {
		logger().log(logger::debug_trace, "SSH kex sending packet [type={}]", Packet::packet_type);
		return send_packet<Packet>(bpacket_, output_, std::forward<Args>(args)...);
	}

	kex_init_data const& init_data() const { return init_data_; }
	crypto_context const& ccontext() const { return ccontext_; }
	crypto_call_context const& call_context() const { return call_context_; }
	ssh::logger& logger() const { return call_context_.log; }

private:
	ssh_config const& config_;
	ssh_binary_packet& bpacket_;
	out_buffer& output_;
	kex_init_data const& init_data_;
	crypto_context const& ccontext_;
	crypto_call_context call_context_;
};

std::unique_ptr<kex> construct_kex(kex_type, kex_context);

}

#endif
