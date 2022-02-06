
#include "ssh_transport.hpp"
#include "protocol_helpers.hpp"
#include "transport_message.hpp"

namespace securepath::ssh {

ssh_transport::ssh_transport(ssh_config const& c, out_buffer& b, logger& l)
: config_(c)
, output_(b)
, logger_(l)
{
}

void ssh_transport::on_version_exchange(ssh_version const& v) {
	logger_.log(logger::info, "Client version exchange [ssh={}, software={}]", v.ssh, v.software);

	if(v.ssh != "2.0") {
		//unsupported version
		disconnect(ssh_protocol_version_not_supported);
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
		ssh_bp_encoder p{config_, crypto_out_, output_};

		transport_message msg{p, ssh_disconnect, uint32_size + string_size(message.size()) + string_size(0)};
		msg.add_uint32(code);
		msg.add_string(message);
		msg.add_string("");
		msg.done();

		p.send_packet();
	}
	set_state(ssh_state::disconnected);
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
		return layer_op::read_more;
	} else {
		return layer_op::none;
	}
}

layer_op ssh_transport::handle_packet(span payload) {

}

layer_op ssh_transport::handle_payload(in_buffer& in) {
	ssh_bp_decoder p{config_, crypto_in_, in};

	if(!crypto_in_.packet_size) {
		if(!p.decode_header()) {
			//t: log message
			disconnect();
			return layer_op::disconnected;
		}
		crypto_in_.packet_size = p.packet_size();
		crypto_in_.padding_size = p.padding_size();
		if(crypto_in_.packet_size > in.size()) {
			return layer_op::want_more;
		}
	}

	if(p.decode()) {
		handle_packet(p.payload());
		crypto_in_.packet_size = 0;
		crypto_in_.padding_size = 0;
	} else {
		//t: log message
		disconnect();
		return layer_op::disconnected;
	}
	return layer_op::none;
}

layer_op ssh_transport::handle_binary_packet(in_buffer& in) {


	// if we haven't extracted header yet or we have enough bytes, try to handle the packet
	if(!crypto_in_.packet_size || crypto_in_.packet_size <= in.size()) {
		return handle_payload(in);
	}

	// not enough data
	return layer_op::want_more;
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

}
