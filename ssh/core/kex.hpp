#ifndef SP_SHH_KEX_HEADER
#define SP_SHH_KEX_HEADER

#include "errors.hpp"
#include "ssh/crypto/crypto_context.hpp"

#include <iosfwd>
#include <optional>
#include <string_view>
#include <vector>

namespace securepath::ssh {

enum class kex_type {
	unknown = 0,
	dh_group14_sha256,
	curve25519_sha256,
	ecdh_sha2_nistp256
};

std::string_view to_string(kex_type);
kex_type from_string(type_tag<kex_type>, std::string_view);

enum class kex_state {
	none,
	inprogress,
	succeeded,
	error
};

struct crypto_configuration {
	kex_type kex{};
	key_type host_key{};

	struct ctripled {
		cipher_type cipher{};
		mac_type mac{};
		compress_type compress{};

		friend bool operator==(ctripled const&, ctripled const&) = default;
	} in, out;

	friend bool operator==(crypto_configuration const&, crypto_configuration const&) = default;
};


class kex {
public:
	virtual ~kex() = default;

	// interface to get kex result data
	virtual kex_state initiate() = 0;

	ssh_error_code error() const {
		return error_;
	}

	std::string error_message() const {
		return err_message_;
	}

	virtual crypto_configuration crypto_config() const = 0;
protected:
	ssh_error_code error_;
	std::string err_message_;
};

std::ostream& operator<<(std::ostream&, crypto_configuration const&);

class ssh_config;
class supported_algorithms;

std::optional<crypto_configuration> crypto_config_guess(supported_algorithms const&, transport_side);

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
		, crypto_context const& ccontext, crypto_call_context call_context, crypto_configuration cconfig)
	: config_(config)
	, bpacket_(bpacket)
	, output_(output)
	, init_data_(init_data)
	, ccontext_(ccontext)
	, call_context_(call_context)
	, crypto_config_(cconfig)
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
	crypto_configuration crypto_config() const { return crypto_config_; }

private:
	ssh_config const& config_;
	ssh_binary_packet& bpacket_;
	out_buffer& output_;
	kex_init_data const& init_data_;
	crypto_context const& ccontext_;
	crypto_call_context call_context_;
	crypto_configuration crypto_config_;
};

std::unique_ptr<kex> construct_kex(kex_context);

}

#endif
