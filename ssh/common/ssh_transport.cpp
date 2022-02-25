
#include "ssh_transport.hpp"
#include "protocol_helpers.hpp"
#include "packet_ser_impl.hpp"

namespace securepath::ssh {

ssh_transport::ssh_transport(ssh_config const& c, out_buffer& b, logger& l)
: config_(c)
, output_(b)
, logger_(l)
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
	//t: debug check for state changes
	state_ = s;
}

/*
   byte      SSH_MSG_DISCONNECT
   uint32    reason code
   string    description in ISO-10646 UTF-8 encoding [RFC3629]
   string    language tag [RFC3066]
*/
void ssh_transport::disconnect(std::uint32_t code, std::string_view message) {
	logger_.log(logger::debug, "SSH disconnect [state={}, code={}, msg={}]", state(), code, message);

	if(state() != ssh_state::none && state() != ssh_state::disconnected) {
		send_packet<ser::disconnect>(code, message, "");
		/*send_packet( [&](span out) {
			ser::disconnect::save s(code, message, "");
			return s.write(out);
		});*/
	}
	set_state(ssh_state::disconnected);
}

void ssh_transport::set_error_and_disconnect(ssh_error_code code) {
	error_ = code;
	disconnect(code);
}

layer_op ssh_transport::handle_version_exchange(in_buffer& in) {
	if(state() == ssh_state::none) {
		if(!send_version_string(config_.my_version, output_)) {
			set_state(ssh_state::disconnected);
		} else {
			set_state(ssh_state::version_exchange);
		}
	}
	if(state() == ssh_state::version_exchange) {
		if(!client_version_received_) {
			auto res = parse_ssh_version(in, false, client_version_);
			if(res == version_parse_result::ok) {
				client_version_received_ = true;
				set_state(ssh_state::kex);
				on_version_exchange(client_version_);
			} else if(res == version_parse_result::error) {
				set_state(ssh_state::disconnected);
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

	if(crypto_in_.current_packet.status == packet_status::waiting_header) {
		if(!try_decode_header(data)) {
			return layer_op::want_read_more;
		}
	}

	if(crypto_in_.current_packet.status == packet_status::waiting_data) {
		// see if we have whole packet already
		if(crypto_in_.current_packet.packet_size <= data.size()) {
			crypto_in_.current_packet.payload = decrypt_packet(data, data);
		} else {
			return layer_op::want_read_more;
		}
	}

	if(crypto_in_.current_packet.status == packet_status::data_ready) {
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
	if(state() == ssh_state::none || state() == ssh_state::version_exchange) {
		return handle_version_exchange(in);
	}

	return handle_binary_packet(in);
}

layer_op ssh_transport::process_transport_payload(span payload) {
	SPSSH_ASSERT(payload.size() >= 1, "invalid payload size");
	ssh_packet_type type = ssh_packet_type(std::to_integer<std::uint8_t>(payload[0]));
	logger_.log(logger::debug, "SSH process_transport_packet [type={}]", type);
	if(handle_transport_payload(type, payload.subspan(1))) {
		crypto_in_.current_packet.clear();
	}
	return layer_op::none;
}

bool ssh_transport::handle_transport_payload(ssh_packet_type type, const_span payload) {
	ssh_bf_reader read(payload);

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
		return true;

	} else if(type == ssh_ignore) {

	} else if(type == ssh_unimplemented) {

	} else if(type == ssh_debug) {

	}

	return false;
}

span ssh_transport::get_out_buffer(std::size_t size) {
	return {};
}

void ssh_transport::commit_out_buffer(span buf, std::size_t size) {

}

template<typename Packet, typename... Args>
bool ssh_transport::send_packet(Args&&... args) {
	logger_.log(logger::debug_trace, "SSH sending packet [type={}]", Packet::packet_type);

	typename Packet::save packet(std::forward<Args>(args)...);
	std::size_t size = packet.size();
	span buf = get_out_buffer(size);
	bool ret = !buf.empty();
	if(ret) {
		ret = packet.write(buf);
		if(ret) {
			commit_out_buffer(buf, packet.serialised_size());
		} else {
			logger_.log(logger::debug, "SSH send_packet failed to serialise packet [type={}]", Packet::packet_type);
		}
	} else {
		logger_.log(logger::debug, "SSH send_packet could not get enough buffer to send packet [size={}, type={}]", size, Packet::packet_type);
	}
	return ret;
}

}
