#include "config_parser.hpp"
#include "util.hpp"

#include "config.hpp"

#if defined(USE_NETTLE) && defined(USE_CRYPTOPP)
#	include "ssh/crypto/nettle/crypto_context.hpp"
#	include "ssh/crypto/cryptopp/crypto_context.hpp"
#endif

#include <iostream>

namespace securepath::ssh {

void config_parser::add_commands(command_parser& p) {
	p.add(crypto_, "crypto", "", "Choose crypto backend");

	p.add(version_.ssh, "version-ssh", "", "SSH version");
	p.add(version_.software, "version-software", "", "SSH software");
	p.add(version_.comment, "version-comment", "", "SSH comment");

	p.add(kexes_, "kex", "", "Supported kexes in order of preference");
	p.add(host_keys_, "host-key", "", "Supported host keys in order of preference");
	p.add(client_server_ciphers_, "client-server-cipher", "", "Supported client-server ciphers in order of preference");
	p.add(server_client_ciphers_, "server-client-cipher", "", "Supported server-client ciphers in order of preference");
	p.add(client_server_macs_, "client-server-mac", "", "Supported client-server macs in order of preference");
	p.add(server_client_macs_, "server-client-mac", "", "Supported server-client macs in order of preference");
	p.add(private_keys_, "private-key", "", "Private keys");
	p.add(rekey_data_interval_, "rekey-data-interval", "", "Rekey data interval in kilo bytes");
	p.add(rekey_time_interval_, "rekey-time-interval", "", "Rekey time interval in seconds");
	p.add(max_out_buffer_size_, "max-out-buffer_size", "", "Maximum size of output buffer in kilo bytes");
	p.add(shrink_out_buffer_size_, "shrink-out-buffer-size", "", "Size to which the output buffer is shrinked");
	p.add(max_in_packet_size_, "max-in-packet-size", "", "Maximum size of input packet size in kilo bytes");
	p.add(max_out_packet_size_, "max-out-packet-size", "", "Maximum size of output packet size in kilo bytes");

	p.add(channel_max_packet_size_, "channel-max-packet-size", "", "Maximum packet size for channels in kilo bytes");
	p.add(channel_initial_window_size_, "channel-initial-window-size", "", "Initial window size for channels in kilo bytes");

	p.add(random_packet_padding_, "random-packet-padding", "", "Switch on random packet padding");
	p.add(guess_kex_packet_, "guess-kex-packet", "", "Send 'guess' kex packet before response");

}

template<typename Type, typename List>
static void parse_param(std::vector<std::string> const& vec, List& list, std::string name) {
	if(!vec.empty()) {
		list.clear();
		for(auto&& v : vec) {
			auto k = from_string(type_tag<Type>{}, v);
			if(k == Type::unknown) {
				throw invalid_argument("unknown " + name + ": '" + v + "'");
			}
			list.add_back(k);
		}
	}
}

void config_parser::instantiate_crypto() {
	if(crypto_ == "nettle") {
#ifdef USE_NETTLE
		ccontext_ = nettle::create_nettle_context();
#else
		throw invalid_argument("Not built with nettle support");
#endif
	} else if(crypto_ == "cryptopp") {
#ifdef USE_CRYPTOPP
		ccontext_ = cryptopp::create_cryptopp_context();
#else
		throw invalid_argument("Not built with cryptopp support");
#endif
	} else if(crypto_.empty()) {
		ccontext_ = default_crypto_context();
	} else {
		throw invalid_argument("Invalid crypto backend");
	}
}

void config_parser::parse(logger& log, ssh_config& c) {
	instantiate_crypto();

	// first load the private keys and after that handle the host_keys, so that one can use the latter to limit on server side
	if(!private_keys_.empty()) {
		auto rand = ccontext_.construct_random();
		crypto_call_context call(log, *rand);

		c.private_keys.clear();
		for(auto&& v : private_keys_) {
			auto pkey = load_ssh_private_key(read_file(v), ccontext_, call);
			if(!pkey.valid()) {
				throw std::runtime_error("could not load private key: " + v);
			}
			c.add_private_key(pkey);
			if(c.side == transport_side::server) {
				c.algorithms.host_keys.add_back(pkey.type());
			}
		}
	}

	parse_param<kex_type>(kexes_, c.algorithms.kexes, "kex type");
	parse_param<key_type>(host_keys_, c.algorithms.host_keys, "host key type");
	parse_param<cipher_type>(client_server_ciphers_, c.algorithms.client_server_ciphers, "cipher type");
	parse_param<cipher_type>(server_client_ciphers_, c.algorithms.server_client_ciphers, "cipher type");
	parse_param<mac_type>(client_server_macs_, c.algorithms.client_server_macs, "mac type");
	parse_param<mac_type>(server_client_macs_, c.algorithms.server_client_macs, "mac type");
	if(rekey_data_interval_) {
		c.rekey_data_interval = *rekey_data_interval_ * 1024ull;
	}
	if(rekey_time_interval_) {
		c.rekey_time_interval = std::chrono::seconds(*rekey_time_interval_);
	}
	if(max_out_buffer_size_) {
		c.max_out_buffer_size = max_out_buffer_size_ * 1024ul;
	}
	if(shrink_out_buffer_size_) {
		c.shrink_out_buffer_size = shrink_out_buffer_size_ * 1024ul;
	}
	if(max_in_packet_size_) {
		c.max_in_packet_size = max_in_packet_size_ * 1024ul;
	}
	if(max_out_packet_size_) {
		c.max_out_packet_size = max_out_buffer_size_ * 1024ul;
	}
	if(channel_max_packet_size_) {
		c.channel.max_packet_size = channel_max_packet_size_ * 1024ul;
	}
	if(channel_initial_window_size_) {
		c.channel.initial_window_size = channel_initial_window_size_ * 1024ul;
	}
	if(!version_.ssh.empty()) {
		c.my_version.ssh = version_.ssh;
	}
	if(!version_.software.empty()) {
		c.my_version.software = version_.software;
	}
	if(!version_.comment.empty()) {
		c.my_version.comment = version_.comment;
	}
	if(random_packet_padding_) {
		c.random_packet_padding = *random_packet_padding_;
	}
	if(guess_kex_packet_) {
		c.guess_kex_packet = *guess_kex_packet_;
	}
}

}
