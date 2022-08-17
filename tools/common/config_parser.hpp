#ifndef SECUREPATH_TOOLS_COMMON_CONFIG_PARSER_HEADER
#define SECUREPATH_TOOLS_COMMON_CONFIG_PARSER_HEADER

#include "command_parser.hpp"
#include "ssh/common/types.hpp"
#include "ssh/core/ssh_config.hpp"

namespace securepath::ssh {

class config_parser {
public:
	/// add ssh_config options to the command parser
	void add_commands(command_parser&);

	/// throws exception if some of the options contain invalid value
	void parse(logger&, ssh_config&);

	crypto_context get_crypto_context() const { return ccontext_; }
private:
	void instantiate_crypto();

private:
	crypto_context ccontext_;

	std::string crypto_;
	ssh_version version_;
	std::vector<std::string> kexes_;
	std::vector<std::string> host_keys_;
	std::vector<std::string> client_server_ciphers_;
	std::vector<std::string> server_client_ciphers_;
	std::vector<std::string> client_server_macs_;
	std::vector<std::string> server_client_macs_;
	std::vector<std::string> private_keys_;
	std::optional<std::uint64_t> rekey_data_interval_;
	std::optional<std::uint32_t> rekey_time_interval_;
	//std::optional<bool> random_packet_padding_;
	std::uint32_t max_out_buffer_size_{};
	std::uint32_t shrink_out_buffer_size_{};
	std::uint32_t max_in_packet_size_{};
	std::uint32_t max_out_packet_size_{};
	//std::optional<bool> guess_kex_packet_;
	std::uint32_t channel_max_packet_size_{};
	std::uint32_t channel_initial_window_size_{};
};

}

#endif
