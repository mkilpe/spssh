#include "ssh_binary_packet.hpp"

#include "ssh_constants.hpp"
#include "ssh_binary_util.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/common/types.hpp"

namespace securepath::ssh {

ssh_binary_packet::ssh_binary_packet(ssh_config const& config, logger& logger)
: config_(config)
, logger_(logger)
{
}

ssh_config const& ssh_binary_packet::config() const {
	return config_;
}

void ssh_binary_packet::set_random(random& r) {
	random_ = &r;
}

void ssh_binary_packet::set_crypto(stream_crypto& s, std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac) {
	s.cipher = std::move(cipher);
	s.mac = std::move(mac);

	if(s.cipher->is_aead()) {
		s.integrity_size = static_cast<aead_cipher const&>(*s.cipher).tag_size();
	} else {
		SPSSH_ASSERT(s.mac, "Invalid mac");
		s.integrity_size = s.mac->size();
	}

	s.block_size = std::max(minimum_block_size, s.cipher->block_size());
	SPSSH_ASSERT(s.block_size < maximum_padding_size, "too big cipher block size");
}

void ssh_binary_packet::set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac) {
	logger_.log(logger::debug, "SSH starting to decrypt incoming packets");

	set_crypto(stream_in_, std::move(cipher), std::move(mac));
	stream_in_.tag_buffer.resize(stream_in_.integrity_size);
}

void ssh_binary_packet::set_output_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac) {
	logger_.log(logger::debug, "SSH starting to encrypt outgoing packets");

	set_crypto(stream_out_, std::move(cipher), std::move(mac));
}

bool ssh_binary_packet::try_decode_header(span in_data) {
	if(in_data.size() < stream_in_.block_size) {
		return false;
	}

	// check if the  packet length is encrypted or not
	if(stream_in_.cipher && !stream_in_.cipher->is_aead()) {
		// decrypt just the first block to get the length
		auto block_span = safe_subspan(in_data, 0, stream_in_.block_size);
		stream_in_.cipher->process(block_span, block_span);
	}

	stream_in_.current_packet.packet_size = packet_lenght_size + ntou32(in_data.data()) + stream_in_.integrity_size;
	//t: check the total size is not longer than allowed

	stream_in_.current_packet.status = in_packet_status::waiting_data;
	logger_.log(logger::debug, "SSH try_decode_header [size={}]", stream_in_.current_packet.packet_size);

	return true;
}

span ssh_binary_packet::decrypt_packet(const_span in_data, span out_data) {
	SPSSH_ASSERT(stream_in_.current_packet.packet_size != 0, "Invalid packet size");
	SPSSH_ASSERT(stream_in_.current_packet.packet_size <= in_data.size(), "Invalid data size");

	span payload;

	// are we encrypted?
	if(stream_in_.cipher) {
		if(stream_in_.cipher->is_aead()) {
			payload = decrypt_aead(static_cast<aead_cipher&>(*stream_in_.cipher), in_data, out_data);
		} else {
			payload = decrypt_with_mac(in_data, out_data);
		}
	} else {
		std::uint8_t padding = std::to_integer<std::uint8_t>(in_data[packet_lenght_size]);
		std::size_t size = stream_in_.current_packet.packet_size - packet_header_size - padding;
		if(in_data.size() >= size + packet_header_size) {
			if(in_data.data() != out_data.data()) {
				SPSSH_ASSERT(out_data.size() >= size, "invalid out buffer size");
				std::memcpy(out_data.data(), in_data.data() + packet_header_size, size);
				payload = safe_subspan(out_data, 0, size);
			} else {
				payload = safe_subspan(out_data, packet_header_size, size);
			}
		} else {
			// invalid packet
			set_error(spssh_invalid_packet, "trying to decrypt invalid packet");
		}
	}

	if(!payload.empty()) {
		stream_in_.current_packet.status = in_packet_status::data_ready;
		stream_in_.current_packet.sequence = stream_in_.packet_sequence;
		stream_in_.current_packet.payload = payload;
		stream_in_.transferred_bytes += in_data.size();
		// incremented for every packet and let wrap around
		++stream_in_.packet_sequence;
	}
	return payload;
}


span ssh_binary_packet::decrypt_aead(aead_cipher& cip, const_span data, span out) {
	SPSSH_ASSERT(stream_in_.block_size >= minimum_block_size, "invalid block size");
	SPSSH_ASSERT(stream_in_.current_packet.packet_size >= stream_in_.block_size, "invalid packet size");
	SPSSH_ASSERT(stream_in_.integrity_size > 0, "invalid integrity size");
	SPSSH_ASSERT(stream_in_.tag_buffer.size() == stream_in_.integrity_size, "Invalid tag buffer");

	if(data.data() == out.data()) {
		//if we are doing in place decryption, the in and out for decrypting needs to be same address
		out = safe_subspan(out, packet_lenght_size);
	}

	data = safe_subspan(data, 0, stream_in_.current_packet.packet_size);

	// first handle the non-encrypted authenticated data
	cip.process_auth(safe_subspan(data, 0, packet_lenght_size));
	data = safe_subspan(data, packet_lenght_size);

	// decrypt the data
	cip.process(safe_subspan(data, 0, data.size() - stream_in_.integrity_size), out);

	// get the tag
	cip.tag(stream_in_.tag_buffer);

	// check the tag matches
	if(!compare_equal(stream_in_.tag_buffer
		, safe_subspan(data, data.size() - stream_in_.integrity_size, stream_in_.integrity_size)))
	{
		set_error(ssh_mac_error, "verifying tag failed");
		logger_.log(logger::debug, "SSH decrypt_aead verifying tag failed");
		return span{};
	}

	std::uint8_t padding = std::to_integer<std::uint8_t>(*out.data());
	if(packet_header_size + padding + stream_in_.integrity_size > stream_in_.current_packet.packet_size) {
		set_error(spssh_invalid_packet, "Invalid packet");
		logger_.log(logger::debug, "SSH decrypt_aead invalid packet");
		return span{};
	}
	stream_in_.current_packet.data_size = stream_in_.current_packet.packet_size - packet_header_size - padding - stream_in_.integrity_size;
	return safe_subspan(out, padding_size, stream_in_.current_packet.data_size);
}

span ssh_binary_packet::decrypt_with_mac(const_span data, span out) {
	SPSSH_ASSERT(stream_in_.block_size >= minimum_block_size, "invalid block size");
	SPSSH_ASSERT(stream_in_.current_packet.packet_size >= stream_in_.block_size, "invalid packet size");
	SPSSH_ASSERT(stream_in_.integrity_size > 0, "invalid integrity size");
	SPSSH_ASSERT(stream_in_.tag_buffer.size() == stream_in_.integrity_size, "Invalid tag buffer");

	// here the first block is already decrypted so that we found the packet_length
	std::uint8_t padding = std::to_integer<std::uint8_t>(data[packet_lenght_size]);

	// if we are not doing decryption in place, copy the first block to out as it is already decrypted
	if(data.data() != out.data()) {
		std::memcpy(out.data(), data.data(), stream_in_.block_size);
	}

	std::size_t decrypt_size = stream_in_.current_packet.packet_size - stream_in_.block_size - stream_in_.integrity_size;
	stream_in_.cipher->process(safe_subspan(data, stream_in_.block_size, decrypt_size), safe_subspan(out, stream_in_.block_size, decrypt_size));

	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(stream_in_.packet_sequence, seq_buf);

	stream_in_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	stream_in_.mac->process(safe_subspan(out, 0, stream_in_.current_packet.packet_size - stream_in_.integrity_size));

	// get the mac
	stream_in_.mac->result(stream_in_.tag_buffer);

	// check the tag matches
	if(!compare_equal(stream_in_.tag_buffer
		, safe_subspan(data, stream_in_.current_packet.packet_size - stream_in_.integrity_size, stream_in_.integrity_size)))
	{
		error_ = ssh_mac_error;
		logger_.log(logger::debug, "SSH decrypt_with_mac verifying mac failed");
		return span{};
	}

	if(packet_header_size + padding + stream_in_.integrity_size > stream_in_.current_packet.packet_size) {
		set_error(spssh_invalid_packet, "Invalid packet");
		logger_.log(logger::debug, "SSH decrypt_with_mac invalid packet");
		return span{};
	}
	stream_in_.current_packet.data_size = stream_in_.current_packet.packet_size - packet_header_size - padding - stream_in_.integrity_size;
	return span{safe_subspan(out, packet_header_size, stream_in_.current_packet.data_size)};
}

ssh_error_code ssh_binary_packet::error() const {
	return error_;
}

std::string ssh_binary_packet::error_message() const {
	return error_msg_;
}

void ssh_binary_packet::set_error(ssh_error_code code, std::string_view message) {
	error_ = code;
	error_msg_ = message;
}

bool ssh_binary_packet::resize_out_buffer(std::size_t size) {
	logger_.log(logger::debug_trace, "SSH resize_out_buffer [size={}, buf size={}, buf used={}]", size, stream_out_.buffer.size(), stream_out_.data.size());

	std::size_t used_size = stream_out_.data.size();
	std::size_t free_size = stream_out_.buffer.size() - used_size;

	bool ret = free_size < size;
	if(ret) {
		std::size_t new_size = stream_out_.buffer.size() + size - free_size;
		ret = new_size <= config_.max_out_buffer_size;
		if(ret) {
			stream_out_.buffer.resize(new_size);
			stream_out_.data = span(stream_out_.buffer).subspan(0, used_size);
		} else {
			set_error(ssh_error_code::spssh_memory_error, "asking for bigger buffer than max_out_buffer_size");
		}
	}

	return ret;
}

void ssh_binary_packet::shrink_out_buffer() {
	if(stream_out_.data.empty() && config_.shrink_out_buffer_size < stream_out_.buffer.size()) {
		logger_.log(logger::debug_verbose, "SSH shrink_out_buffer [old size={}, new size={}]", stream_out_.buffer.size(), config_.shrink_out_buffer_size);
		stream_out_.buffer.resize(config_.shrink_out_buffer_size);
		stream_out_.buffer.shrink_to_fit();
	}
}

std::optional<out_packet_record> ssh_binary_packet::alloc_out_packet(std::size_t data_size, out_buffer& buf) {

	std::size_t padding_size = minimum_padding(packet_header_size + data_size);
	if(config_.random_packet_padding) {
		SPSSH_ASSERT(random_, "random generator not set");
		// add random padding to make traffic analysing harder
		std::size_t max = (maximum_padding_size - padding_size) / stream_out_.block_size;
		if(max) {
			padding_size += random_->random_uint(0, max) * stream_out_.block_size;
			logger_.log(logger::debug_verbose, "SSH adding random padding [size={}]", padding_size);
		}
	}

	out_packet_record res
		{ packet_header_size + data_size + padding_size + stream_out_.integrity_size
		, data_size
		, padding_size
		};

	// check if we don't have pending data to write out
	if(stream_out_.data.empty()) {
		logger_.log(logger::debug_trace, "SSH trying inplace sending");

		res.data_buffer = buf.get(res.size);
	}

	// remember if we are in-place allocated, so that we know to commit after sending
	res.inplace = !res.data_buffer.empty();

	if(!res.inplace) {
		if(!resize_out_buffer(res.size)) {
			logger_.log(logger::info, "SSH alloc_out_packet failed to allocate data buffer [size={}]", res.size);
			return std::nullopt;
		}
		res.data_buffer = safe_subspan(stream_out_.buffer, stream_out_.data.size());
	}

	res.data = safe_subspan(res.data_buffer, packet_header_size, data_size);

	return res;
}

std::size_t ssh_binary_packet::minimum_padding(std::size_t header_payload_size) const {
	if(stream_out_.cipher && stream_out_.cipher->is_aead()) {
		// the encrypted part needs to be modulo block_size, but the length is not encrypted
		header_payload_size -= packet_lenght_size;
	}
	std::size_t res = stream_out_.block_size - (header_payload_size % stream_out_.block_size);
	if(res < minimum_padding_size) {
		// at least some padding is required always
		res += stream_out_.block_size;
	}
	return res;
}

void ssh_binary_packet::aead_encrypt(aead_cipher& cip, const_span data, span out) {
	// authenticate the packet length as we don't encrypt it
	cip.process_auth(safe_subspan(data, 0, packet_lenght_size));
	// if we are not doing things _in place_, copy the packet length to output buffer
	if(data.data() != out.data()) {
		std::memcpy(out.data(), data.data(), packet_lenght_size);
	}
	data = safe_subspan(data, packet_lenght_size);
	out = safe_subspan(out, packet_lenght_size);
	// encrypt rest of the data
	cip.process(data, out);
	// add authentication tag at the end
	cip.tag(safe_subspan(out, data.size(), stream_out_.integrity_size));
}

void ssh_binary_packet::encrypt_with_mac(const_span data, span out) {
	// mac = MAC(key, sequence_number || unencrypted_packet)
	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(stream_out_.packet_sequence, seq_buf);
	stream_out_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	stream_out_.mac->process(data);
	// add mac at the end
	stream_out_.mac->result(safe_subspan(out, data.size()));
	// encrypt the packet
	stream_out_.cipher->process(data, safe_subspan(out, 0, data.size()));
}

void ssh_binary_packet::encrypt_packet(const_span data, span out) {
	if(stream_out_.cipher) {
		if(stream_out_.cipher->is_aead()) {
			aead_encrypt(static_cast<aead_cipher&>(*stream_out_.cipher), data, out);
		} else {
			SPSSH_ASSERT(stream_out_.mac, "MAC object not set");
			encrypt_with_mac(data, out);
		}
	} else if(data.data() != out.data()) {
		SPSSH_ASSERT(out.size() >= data.size(), "invalid out buffer size");
		std::memcpy(out.data(), data.data(), data.size());
	}
}

bool ssh_binary_packet::create_out_packet(out_packet_record const& info, out_buffer& out_buf) {
	logger_.log(logger::debug_trace, "SSH create_out_packet [size={}, payload_size={}, padding_size={}]", info.size, info.payload_size, info.padding_size);
	SPSSH_ASSERT(random_, "random generator not set");

	ssh_bf_writer p(info.data_buffer);

	bool ret = p.write(std::uint32_t(1 + info.payload_size + info.padding_size)) // padding_length + payload + padding
		&& p.write(std::uint8_t(info.padding_size))
		&& p.jump_over(info.payload_size) // just jump over the payload bytes as those have been written there already
		&& p.add_random_range(*random_, info.padding_size);

	if(ret) {
		encrypt_packet(safe_subspan(info.data_buffer, 0, info.size - stream_out_.integrity_size), info.data_buffer);

		// incremented for every packet and let wrap around
		++stream_out_.packet_sequence;
		stream_out_.transferred_bytes += info.size;

		if(info.inplace) {
			out_buf.commit(info.size);
		} else {
			stream_out_.data = info.data_buffer;
		}
	}
	return ret;
}

bool ssh_binary_packet::send_pending(out_buffer& out) {
	logger_.log(logger::debug_trace, "SSH send_pending [data size={}]", stream_out_.data.size());

	if(!stream_out_.data.empty()) {
		std::size_t ask_size = std::min(out.size(), stream_out_.data.size());
		if(ask_size) {
			auto buf = out.get(ask_size);
			if(!buf.empty()) {
				copy(safe_subspan(stream_out_.data, 0, ask_size), buf);
				out.commit(ask_size);

				if(stream_out_.data.size() > ask_size) {
					span left = safe_subspan(stream_out_.data, ask_size);
					std::memmove(stream_out_.buffer.data(), left.data(), left.size());
					stream_out_.data = safe_subspan(stream_out_.buffer, 0, left.size());
				} else {
					stream_out_.data = span();
					shrink_out_buffer();
				}
			}
		}
	}

	return stream_out_.data.empty();
}

}

