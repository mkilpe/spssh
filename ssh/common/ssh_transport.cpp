
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

ssh_error_code ssh_transport::error() const {
	return error_;
}

std::string ssh_transport::error_message() const {
	return error_msg_;
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
		send_packet( [&](span out) {
			ser::disconnect::save s(code, message, "");
			return s.write(out);
		});
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
		return layer_op::read_more;
	} else {
		return layer_op::none;
	}
}

layer_op ssh_transport::handle_packet(span payload) {

}

layer_op ssh_transport::handle_binary_packet(in_buffer& in) {

	if(crypto_in_.current_packet.status == packet_status::waiting_header) {
		if(!try_decode_header(in.get())) {
			return layer_op::want_more;
		}
	}

	if(crypto_in_.current_packet.status == packet_status::waiting_data) {
		// see if we have whole packet already
		if(crypto_in_.current_packet.packet_size <= in.size()) {
			auto data = in.get();
			crypto_in_.current_packet.payload = decrypt_packet(data, data);
		} else {
			return layer_op::want_more;
		}
	}

	if(crypto_in_.current_packet.status == packet_status::data_ready) {
		return process_transport_packet(crypto_in_.current_packet.payload);
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

bool ssh_transport::set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac) {
	logger_.log(logger::debug, "SSH starting to encrypt");

	crypto_in_.cipher = std::move(cipher);
	crypto_in_.mac = std::move(mac);

	if(crypto_in_.cipher->is_aead()) {
		crypto_in_.integrity_size = static_cast<aead_cipher const&>(*crypto_in_.cipher).tag_size();
	} else {
		SPSSH_ASSERT(crypto_in_.mac, "Invalid mac");
		crypto_in_.integrity_size = crypto_in_.mac->size();
	}

	crypto_in_.block_size = std::max(minimum_block_size, crypto_in_.cipher->cipher_block_size());
	SPSSH_ASSERT(crypto_in_.block_size < maximum_padding_size, "too big cipher block size");

	crypto_in_.tag_buffer.resize(crypto_in_.integrity_size);
}

bool ssh_transport::try_decode_header(span in_data) {
	if(data.size() < crypto_in_.block_size) {
		return false;
	}

	// check if the  packet length is encrypted or not
	if(crypto_in_.cipher && !crypto_in_.cipher->is_aead()) {
		// decrypt just the first block to get the length
		auto block_span = data_.subspan(0, crypto_in_.block_size);
		crypto_in_.cipher->process(block_span, block_span);
	}

	crypto_in_.current_packet.packet_size = packet_lenght_size + ntou32(data_.data()) + integrity_size_;
	crypto_in_.current_packet.status = packet_status::waiting_data;
	logger_.log(logger::debug, "SSH try_decode_header [size={}]", crypto_in_.packet_header.packet_size);

	return true;
}

span ssh_transport::decrypt_packet(const_span in_data, span out_data) {
	SPSSH_ASSERT(crypto_in_.current_packet.packet_size <= in_data.size(), "Invalid data size");

	span ret;

	// are we encrypted?
	if(crypto_in_.cipher) {
		if(crypto_in_.cipher->is_aead()) {
			ret = decrypt_aead(static_cast<aead_cipher&>(*crypto_in_), in_data, out_data);
		} else {
			ret = decrypt_with_mac(in_data, out_data);
		}
	} else {
		std::uint8_t padding = std::to_integer<std::uint8_t>(data.data() + packet_lenght_size);
		ret = span{out_data.subspan(packet_header_size, crypto_in_.current_packet.packet_size - packet_header_size - padding)};
	}

	if(!ret.empty()) {
		crypto_in_.current_packet.status = packet_status::data_ready;
		// incremented for every packet and let wrap around
		++crypto_in_.packet_sequence;
	}
	return ret;
}


span ssh_transport::decrypt_aead(aead_cipher& cip, const_span data, span out) {
	SPSSH_ASSERT(crypto_out_.block_size >= minimum_block_size, "invalid block size");
	SPSSH_ASSERT(crypto_out_.current_packet.packet_size >= crypto_out_.block_size, "invalid packet size");
	SPSSH_ASSERT(crypto_out_.integrity_size > 0, "invalid integrity size");
	SPSSH_ASSERT(crypto_in_.tag_buffer.size() == crypto_out_.integrity_size, "Invalid tag buffer");

	// first handle the non-encrypted authenticated data
	cip.process_auth(data.subspan(0, packet_lenght_size));
	data = data.subspan(packet_lenght_size);

	// decrypt the data
	cip.process(data, out);

	// get the tag
	cip.tag(crypto_in_.tag_buffer);

	// check the tag matches
	if(std::memcmp(crypto_in_.tag_buffer.data()
		, data.data() + crypto_in_.current_packet.packet_size - crypto_in_.integrity_size
		, crypto_in_.integrity_size) != 0)
	{
		error_ = ssh_mac_error;
		logger_.log(logger::debug, "SSH decrypt_aead verifying tag failed");
		return span{};
	}

	std::uint8_t padding = std::to_integer<std::uint8_t>(out.data());
	crypto_in_.current_packet.data_size = crypto_in_.current_packet.packet_size - packet_header_size - padding - crypto_in_.integrity_size;
	return span{out.subspan(padding_size, crypto_in_.current_packet.data_size)};
}

span ssh_transport::decrypt_with_mac(const_span data, span out) {
	SPSSH_ASSERT(crypto_out_.block_size >= minimum_block_size, "invalid block size");
	SPSSH_ASSERT(crypto_out_.current_packet.packet_size >= crypto_out_.block_size, "invalid packet size");
	SPSSH_ASSERT(crypto_out_.integrity_size > 0, "invalid integrity size");
	SPSSH_ASSERT(crypto_in_.tag_buffer.size() == crypto_out_.integrity_size, "Invalid tag buffer");

	// here the first block is already decrypted so that we found the packet_length
	std::uint8_t padding = std::to_integer<std::uint8_t>(data.data() + packet_lenght_size);

	// if we are not doing decryption in place, copy the first block to out
	if(data.data() != out.data()) {
		std::memcpy(out.data(), data.data(), crypto_out_.block_size);
	}
	data = data.subspan(crypto_out_.block_size);

	std::size_t decrypt_size = crypto_out_.current_packet.packet_size - crypto_out_.block_size;
	crypto_out_.cipher.process(data.subspan(0, decrypt_size), out.subspan(crypto_out_.block_size, decrypt_size));

	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(crypto_out_.packet_sequence, seq_buf);

	crypto_out_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	crypto_out_.mac->process(out.subspan(0, crypto_out_.current_packet.packet_size - crypto_out_.integrity_size));

	// get the mac
	crypto_out_.mac->result(crypto_in_.tag_buffer);

	// check the tag matches
	if(std::memcmp(crypto_in_.tag_buffer.data()
		, out.data() + crypto_out_.current_packet.packet_size + crypto_out_.integrity_size
		, crypto_out_.integrity_size) != 0)
	{
		error_ = ssh_mac_error;
		logger_.log(logger::debug, "SSH decrypt_with_mac verifying mac failed");
		return span{};
	}

	crypto_in_.current_packet.data_size = crypto_in_.current_packet.packet_size - packet_header_size - padding - crypto_in_.integrity_size;
	return span{out.subspan(packet_header_size, crypto_in_.current_packet.data_size)};
}

layer_op ssh_transport::process_transport_packet(span payload) {
	SPSSH_ASSERT(payload.size() >= 1, "invalid payload size");
	ssh_packet_type type = payload[0];
	logger_.log(logger::debug, "SSH process_transport_packet [type={}]", type);
	if(handle_transport_packet(type, payload.subspan(1))) {
		crypto_in_.current_packet.clear();
	}
}



virtual bool ssh_transport::handle_transport_payload(ssh_packet_type type, const_span payload) {
	ssh_bf_reader read(payload);

	if(type == ssh_disconnect) {

		ser::disconnect::load packet(payload);
		if(packet) {
			auto & [code, desc] = packet;
			error_ = code;
			error_msg_ = desc;
		}
		set_state(ssh_state::disconnected);

		logger_.log(logger::debug, "SSH Disconnect from remote [code={}, msg={}]", error_, error_msg_);

	} else if(type == ssh_ignore) {

	} else if(type == ssh_unimplemented) {

	} else if(type == ssh_debug) {

	} else {

	}
}

}
