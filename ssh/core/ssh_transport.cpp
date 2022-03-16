
#include "ssh_transport.hpp"
#include "protocol_helpers.hpp"
#include "packet_ser_impl.hpp"

#include <ostream>

namespace securepath::ssh {

char const* const state_strings[] =
	{ "none"
	, "version_exchange"
	, "kex"
	, "transport"
	, "user_authentication"
	, "subsystem"
	, "disconnected"
	};

std::string_view to_string(ssh_state s) {
	return state_strings[std::size_t(s)];
}

std::ostream& operator<<(std::ostream& out, ssh_state state) {
	return out << to_string(state);
}

ssh_transport::ssh_transport(ssh_config const& c, out_buffer& b, logger& l)
: ssh_binary_packet(c, l)
, output_(b)
{
}

void ssh_transport::on_version_exchange(ssh_version const& v) {
	logger_.log(logger::info, "SSH version exchange [remote ssh={}, remote software={}]", v.ssh, v.software);

	if(v.ssh != "2.0") {
		logger_.log(logger::error, "SSH invalid remote version [{} != 2.0]", v.ssh);
		//unsupported version
		set_error_and_disconnect(ssh_protocol_version_not_supported);
	}
}

ssh_state ssh_transport::state() const {
	return state_;
}

void ssh_transport::set_state(ssh_state s) {
	SPSSH_ASSERT(state_ != ssh_state::disconnected, "already in disconnected state");
	//t: debug check for state changes
	state_ = s;
}

void ssh_transport::disconnect(std::uint32_t code, std::string_view message) {
	logger_.log(logger::debug, "SSH disconnect [state={}, code={}, msg={}]", to_string(state()), code, message);

	if(state() != ssh_state::none && state() != ssh_state::disconnected) {
		send_packet<ser::disconnect>(code, message, "");
	}
	set_state(ssh_state::disconnected);
}

void ssh_transport::set_error_and_disconnect(ssh_error_code code) {
	logger_.log(logger::debug_trace, "SSH setting error [error={}]", code);
	SPSSH_ASSERT(error_ == ssh_noerror, "already error set");
	error_ = code;
	disconnect(code);
}

layer_op ssh_transport::handle_version_exchange(in_buffer& in) {
	logger_.log(logger::debug_trace, "SSH handle_version_exchange [state={}]", to_string(state()));
	if(state() == ssh_state::none) {
		if(!send_version_string(config_.my_version, output_)) {
			set_state(ssh_state::disconnected);
		} else {
			set_state(ssh_state::version_exchange);
		}
	}
	if(state() == ssh_state::version_exchange) {
		if(!remote_version_received_) {
			auto res = parse_ssh_version(in, false, remote_version_);
			if(res == version_parse_result::ok) {
				remote_version_received_ = true;
				on_version_exchange(remote_version_);
				if(error_ == ssh_noerror) {
					set_state(ssh_state::kex);
				}
			} else if(res == version_parse_result::error) {
				set_error(ssh_protocol_error, "failed to parse protocol version information");
				set_state(ssh_state::disconnected);
			} else {
				logger_.log(logger::debug_trace, "parse_ssh_version requires more data");
			}
		}
	}
	if(state() == ssh_state::disconnected) {
		return layer_op::disconnected;
	} else if(state() == ssh_state::version_exchange) {
		return layer_op::want_read_more;
	} else {
		return layer_op::none;
	}
}

layer_op ssh_transport::handle_binary_packet(in_buffer& in) {
	auto data = in.get();

	if(crypto_in_.current_packet.status == in_packet_status::waiting_header) {
		if(!try_decode_header(data)) {
			return layer_op::want_read_more;
		}
	}

	if(crypto_in_.current_packet.status == in_packet_status::waiting_data) {
		// see if we have whole packet already
		if(crypto_in_.current_packet.packet_size <= data.size()) {
			crypto_in_.current_packet.payload = decrypt_packet(data, data);
		} else {
			return layer_op::want_read_more;
		}
	}

	if(crypto_in_.current_packet.status == in_packet_status::data_ready) {
		return process_transport_payload(crypto_in_.current_packet.payload);
	}

	// if we get here something went wrong, disconnect...
	set_error_and_disconnect(ssh_protocol_error);

	return layer_op::disconnected;
}

layer_op ssh_transport::handle(in_buffer& in) {
	if(state() == ssh_state::disconnected) {
		return layer_op::disconnected;
	}

	if(!send_pending(output_)) {
		return layer_op::want_write_more;
	}

	if(state() == ssh_state::none || state() == ssh_state::version_exchange) {
		return handle_version_exchange(in);
	}

	if(state() == ssh_state::kex && kex_data_.local_kexinit.empty()) {
		//send kexinit if we haven't done so yet
		return send_kex_init(config_.guess_kex_packet)
			? layer_op::want_read_more : layer_op::disconnected;
	}

	layer_op r = handle_binary_packet(in);
	return state() == ssh_state::disconnected ? layer_op::disconnected : r;
}

layer_op ssh_transport::process_transport_payload(span payload) {
	SPSSH_ASSERT(payload.size() >= 1, "invalid payload size");
	ssh_packet_type type = ssh_packet_type(std::to_integer<std::uint8_t>(payload[0]));
	logger_.log(logger::debug, "SSH process_transport_packet [type={}]", type);

	if(state() == ssh_state::kex) {
		// give whole payload as we need to save it for kex
		return handle_kex_packet(type, payload);
	} else if(handle_transport_payload(type, payload.subspan(1))) {
		crypto_in_.current_packet.clear();
	}
	return layer_op::none;
}

bool ssh_transport::handle_transport_payload(ssh_packet_type type, const_span payload) {
	if(type == ssh_disconnect) {
		ser::disconnect::load packet(payload);
		if(packet) {
			auto & [code, desc, ignore] = packet;
			error_ = ssh_error_code(code);
			error_msg_ = desc;
		} else {
			logger_.log(logger::debug, "SSH Invalid disconnect packet from remote");
		}
		set_state(ssh_state::disconnected);

		logger_.log(logger::info, "SSH Disconnect from remote [code={}, msg={}]", error_, error_msg_);
	} else if(type == ssh_ignore) {
		ser::ignore::load packet(payload);
		if(packet) {
			logger_.log(logger::debug_trace, "SSH ignore packet received");
		} else {
			logger_.log(logger::debug_trace, "SSH received invalid ignore packet");
			set_error_and_disconnect(ssh_protocol_error);
		}
	} else if(type == ssh_unimplemented) {
		ser::unimplemented::load packet(payload);
		if(packet) {
			auto & [seq] = packet;
			logger_.log(logger::debug, "SSH unimplemented packet received [seq={}]", seq);
		} else {
			logger_.log(logger::debug_trace, "SSH received invalid unimplemented packet");
			set_error_and_disconnect(ssh_protocol_error);
		}
	} else if(type == ssh_debug) {
		ser::debug::load packet(payload);
		if(packet) {
			auto & [always_display, message, lang] = packet;
			logger_.log(logger::debug, "SSH debug packet received [always_display={}, message={}, lange={}]", always_display, message, lang);
		} else {
			logger_.log(logger::debug_trace, "SSH received invalid debug packet");
			set_error_and_disconnect(ssh_protocol_error);
		}
	} else {
		logger_.log(logger::debug, "SSH Unknown packet type, sending unimplemented packet [type={}]", type);
		send_packet<ser::unimplemented>(crypto_in_.packet_sequence-1);
	}

	return true;
}

template<typename Packet, typename... Args>
bool ssh_transport::send_packet(Args&&... args) {
	logger_.log(logger::debug_trace, "SSH sending packet [type={}]", Packet::packet_type);
	return ssh::send_packet<Packet>(*this, output_, std::forward<Args>(args)...);
}

bool ssh_transport::send_kex_init(bool send_first_packet) {
	SPSSH_ASSERT(!kex_, "invalid state");

	if(config_.kexes.empty()) {
		logger_.log(logger::error, "SSH No kex algorithms set, aborting...");
		set_error_and_disconnect(ssh_key_exchange_failed);
		return false;
	}

	kex_cookie_.resize(cookie_size);
	random_bytes(kex_cookie_);

	bool ret = ser::serialise_to_vector<ser::kexinit>(kex_data_.local_kexinit,
		std::span<std::byte const, cookie_size>(kex_cookie_),
		config_.kexes.name_list(),
		config_.host_key_list(),
		config_.client_server_ciphers.name_list(),
		config_.server_client_ciphers.name_list(),
		config_.client_server_macs.name_list(),
		config_.server_client_macs.name_list(),
		config_.client_server_compress.name_list(),
		config_.server_client_compress.name_list(),
		std::vector<std::string_view>(), //languages client to server
		std::vector<std::string_view>(), //languages server to client
		send_first_packet,
		0   // reserved for future use
		);

	if(ret) {
		ret = send_payload(*this, kex_data_.local_kexinit, output_);
	}

	if(ret) {
		if(send_first_packet) {
			send_kex_guess();
		}
	}

	return ret;
}

void ssh_transport::send_kex_guess() {
	//todo
}

layer_op ssh_transport::handle_kex_packet(ssh_packet_type type, const_span payload) {
	if(kexinit_received_) {
		SPSSH_ASSERT(kex_, "invalid state");
		set_error_and_disconnect(ssh_key_exchange_failed);
		return layer_op::disconnected;
	} else {
		// not yet received, so this must be it
		if(type != ssh_kexinit) {
			logger_.log(logger::error, "SSH Received packet other than kexinit [type={}]", type);
			set_error_and_disconnect(ssh_key_exchange_failed);
			return layer_op::disconnected;
		}

		return handle_kexinit_packet(payload);
	}
}


layer_op ssh_transport::handle_kexinit_packet(const_span payload) {
	ser::kexinit::load packet(ser::match_type_t, payload);
	if(!packet) {
		set_error_and_disconnect(ssh_key_exchange_failed);
		logger_.log(logger::error, "SSH Invalid kexinit packet from remove");
		return layer_op::disconnected;
	}

	auto & [
		kex_cookie,
		kexes,
		host_keys,
		client_server_ciphers,
		server_client_ciphers,
		client_server_macs,
		server_client_macs,
		client_server_compress,
		server_client_compress,
		lang_client_server,
		lang_server_client,
		sent_first_packet,
		reserved
			] = packet;

/*	if(ret) {
		kex_data_.remote_kexinit = std::vector<std::byte>{payload.begin(), payload.end()};
	}
*/

	return layer_op::want_write_more; //??
}

}
