#include "ssh_binary_packet.hpp"

#include "ssh_config.hpp"
#include "ssh_constants.hpp"
#include "ssh_binary_format.hpp"
#include "types.hpp"

namespace securepath::ssh {


bool ssh_binary_packet::set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac) {
	logger_.log(logger::debug, "SSH starting to encrypt");

	crypto_in_.cipher = std::move(cipher);
	crypto_in_.mac = std::move(mac);

	if(crypto_in_.cipher->is_aead()) {
		crypto_in_.integrity_size = static_cast<aead_cipher const&>(*crypto_in_.cipher).tag_size();
	} else {
		SPSSH_ASSERT(crypto_in_.mac, "Invalid mac");
		crypto_in_.integrity_size = crypto_in_.mac->size();
	}

	crypto_in_.block_size = std::max(minimum_block_size, crypto_in_.cipher->block_size());
	SPSSH_ASSERT(crypto_in_.block_size < maximum_padding_size, "too big cipher block size");

	crypto_in_.tag_buffer.resize(crypto_in_.integrity_size);

	return true;
}

bool ssh_binary_packet::try_decode_header(span in_data) {
	if(in_data.size() < crypto_in_.block_size) {
		return false;
	}

	// check if the  packet length is encrypted or not
	if(crypto_in_.cipher && !crypto_in_.cipher->is_aead()) {
		// decrypt just the first block to get the length
		auto block_span = in_data.subspan(0, crypto_in_.block_size);
		crypto_in_.cipher->process(block_span, block_span);
	}

	crypto_in_.current_packet.packet_size = packet_lenght_size + ntou32(in_data.data()) + crypto_in_.integrity_size;
	crypto_in_.current_packet.status = packet_status::waiting_data;
	logger_.log(logger::debug, "SSH try_decode_header [size={}]", crypto_in_.current_packet.packet_size);

	return true;
}

span ssh_binary_packet::decrypt_packet(const_span in_data, span out_data) {
	SPSSH_ASSERT(crypto_in_.current_packet.packet_size <= in_data.size(), "Invalid data size");

	span ret;

	// are we encrypted?
	if(crypto_in_.cipher) {
		if(crypto_in_.cipher->is_aead()) {
			ret = decrypt_aead(static_cast<aead_cipher&>(*crypto_in_.cipher), in_data, out_data);
		} else {
			ret = decrypt_with_mac(in_data, out_data);
		}
	} else {
		std::uint8_t padding = std::to_integer<std::uint8_t>(in_data[packet_lenght_size]);
		ret = out_data.subspan(packet_header_size, crypto_in_.current_packet.packet_size - packet_header_size - padding);
	}

	if(!ret.empty()) {
		crypto_in_.current_packet.status = packet_status::data_ready;
		// incremented for every packet and let wrap around
		++crypto_in_.packet_sequence;
	}
	return ret;
}


span ssh_binary_packet::decrypt_aead(aead_cipher& cip, const_span data, span out) {
	SPSSH_ASSERT(crypto_in_.block_size >= minimum_block_size, "invalid block size");
	SPSSH_ASSERT(crypto_in_.current_packet.packet_size >= crypto_in_.block_size, "invalid packet size");
	SPSSH_ASSERT(crypto_in_.integrity_size > 0, "invalid integrity size");
	SPSSH_ASSERT(crypto_in_.tag_buffer.size() == crypto_in_.integrity_size, "Invalid tag buffer");

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

	std::uint8_t padding = std::to_integer<std::uint8_t>(*out.data());
	crypto_in_.current_packet.data_size = crypto_in_.current_packet.packet_size - packet_header_size - padding - crypto_in_.integrity_size;
	return span{out.subspan(padding_size, crypto_in_.current_packet.data_size)};
}

span ssh_binary_packet::decrypt_with_mac(const_span data, span out) {
	SPSSH_ASSERT(crypto_in_.block_size >= minimum_block_size, "invalid block size");
	SPSSH_ASSERT(crypto_in_.current_packet.packet_size >= crypto_in_.block_size, "invalid packet size");
	SPSSH_ASSERT(crypto_in_.integrity_size > 0, "invalid integrity size");
	SPSSH_ASSERT(crypto_in_.tag_buffer.size() == crypto_in_.integrity_size, "Invalid tag buffer");

	// here the first block is already decrypted so that we found the packet_length
	std::uint8_t padding = std::to_integer<std::uint8_t>(data[packet_lenght_size]);

	// if we are not doing decryption in place, copy the first block to out
	if(data.data() != out.data()) {
		std::memcpy(out.data(), data.data(), crypto_in_.block_size);
	}
	data = data.subspan(crypto_in_.block_size);

	std::size_t decrypt_size = crypto_in_.current_packet.packet_size - crypto_in_.block_size;
	crypto_in_.cipher->process(data.subspan(0, decrypt_size), out.subspan(crypto_in_.block_size, decrypt_size));

	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(crypto_in_.packet_sequence, seq_buf);

	crypto_in_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	crypto_in_.mac->process(out.subspan(0, crypto_in_.current_packet.packet_size - crypto_in_.integrity_size));

	// get the mac
	crypto_in_.mac->result(crypto_in_.tag_buffer);

	// check the tag matches
	if(std::memcmp(crypto_in_.tag_buffer.data()
		, out.data() + crypto_in_.current_packet.packet_size + crypto_in_.integrity_size
		, crypto_in_.integrity_size) != 0)
	{
		error_ = ssh_mac_error;
		logger_.log(logger::debug, "SSH decrypt_with_mac verifying mac failed");
		return span{};
	}

	crypto_in_.current_packet.data_size = crypto_in_.current_packet.packet_size - packet_header_size - padding - crypto_in_.integrity_size;
	return span{out.subspan(packet_header_size, crypto_in_.current_packet.data_size)};
}

out_packet_info ssh_binary_packet::out_packet_size(std::size_t data_size) const {
	std::size_t packet_size_without_padding = header_size + data_size + crypto_out_.integrity_size;

	std::size_t padding_size = minimum_padding();
	if(config_.random_packet_padding) {
		// add random padding to make traffic analysing harder
		std::size_t max = (maximum_padding_size - padding_size) / crypto_out_.block_size;
		if(max) {
			// todo: change random_uint to be object
			padding_size += random_uint(0, max) * crypto_out_.block_size;
		}
	}

	return out_packet_info{packet_size_without_padding + padding_size, data_size, padding_size};
}

std::size_t ssh_binary_packet::minimum_padding(std::size_t header_payload_size) const {
	std::size_t res = crypto_out_.block_size - (header_payload_size % crypto_out_.block_size);
	if(res < minimum_padding_size) {
		// at least some padding is required always
		res += crypto_out_.block_size;
	}
	return res;
}

void ssh_binary_packet::aead_encrypt(aead_cipher& cip, const_span data, span out) {
	// authenticate the packet length as we don't encrypt it
	cip.process_auth(data.subspan(0, packet_lenght_size));
	// if we are not doing things _in place_, copy the packet length to output buffer
	if(data.data() != out.data()) {
		std::memcpy(out.data(), data.data(), packet_lenght_size);
	}
	data = data.subspan(packet_lenght_size);
	// encrypt rest of the data
	cip.process(data, out.subspan(packet_lenght_size, data.size()));
	// add authentication tag at the end
	cip.tag(out.subspan(packet_lenght_size+data.size()));
}

void ssh_binary_packet::encrypt_with_mac(const_span data, span out) {
	// mac = MAC(key, sequence_number || unencrypted_packet)
	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(crypto_out_.packet_sequence, seq_buf);
	crypto_out_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	crypto_out_.mac->process(data);
	// add mac at the end
	crypto_out_.mac->result(out.subspan(data.size()));
	// encrypt the packet
	crypto_out_.cipher->process(data, out.subspan(0, data.size()));
}

void ssh_binary_packet::encrypt_packet(const_span data, span out) {
	if(crypto_out_.cipher) {
		if(crypto_out_.is_aead()) {
			aead_encrypt(static_cast<aead_cipher&>(*crypto_out_.cipher), data, out);
		} else {
			SPSSH_ASSERT(crypto_out_.mac, "MAC object not set");
			encrypt_with_mac(data, out);
		}
	}
}

bool ssh_binary_packet::create_out_packet(const_span data, span out) {

}

bool ssh_binary_packet::create_out_packet_in_place(out_packet_info const& info, span data) {
	SPSSH_ASSERT(data.size() == info.payload_size, "invalid payload size");
	SPSSH_ASSERT(!crypto_out_.compression, "can't do in place buffer manipulation with compression");

	ssh_bf_writer p(data);

	p.add_uint32(1 + info.payload_size + info.padding_size); // padding_length + payload + padding
	p.add_uint8(info.padding_size);
	p.jump_over(info.payload_size); // just jump over the payload bytes as those have been written there already
	// todo: change this to use object for randomness
	p.add_random_range(info.padding_size);

	encrypt_packet(p.used_span(), p.total_span());

	// incremented for every packet and let wrap around
	++crypto_out_.packet_sequence;
}

}
