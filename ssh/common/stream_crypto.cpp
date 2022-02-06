#include "stream_crypto.hpp"

#include "ssh_config.hpp"
#include "ssh_binary_format.hpp"

namespace securepath::ssh {

std::size_t const packet_lenght_size = 4;
std::size_t const padding_size = 1;
// header size = packet_length 4 bytes + padding length 1 byte
std::size_t const header_size = packet_lenght_size + padding_size;
std::size_t const maximum_padding_size = 255;

// minimum "block" size, the length of header+payload must be multiple of the "block" size (even for stream ciphers).
std::size_t const minimum_block_size = 8;

// at least 4 bytes of padding is always required per SSH specification
std::size_t const minimum_padding_size = 4;

static std::size_t block_size(stream_crypto& c) {
	std::size_t res = minimum_block_size;
	if(c.cipher) {
	 	res = std::max(res, c.cipher->cipher_block_size());
	 	SPSSH_ASSERT(res < maximum_padding_size, "too big cipher block size");
	}
	return res;
}

ssh_bp_encoder::ssh_bp_encoder(ssh_config const& config, stream_out_crypto& stream, out_buffer& out)
: config_(config)
, stream_(stream)
, out_(out)
, packet_multiplier_(block_size(stream_))
{
}

/*
	if(config_.random_packet_padding) {
		// add random padding to make traffic analysing harder
		std::size_t max = (maximum_padding_size - padding_size) / multiple_of;
		if(max) {
			padding_size += random_uint(0, max) * multiple_of;
		}
	}
*/

std::size_t ssh_bp_encoder::calculate_min_padding(std::size_t header_payload_size) const {
	std::size_t res = packet_multiplier_ - (header_payload_size % packet_multiplier_);
	if(res < minimum_padding_size) {
		// at least some padding is required always
		res += packet_multiplier_;
	}
	return res;
}

std::size_t ssh_bp_encoder::calculate_size(std::size_t size) const {
	std::size_t packet_size = header_size + size;
	packet_size += calculate_min_padding(packet_size);
	if(stream_.cipher) {
		packet_size += stream_.cipher->integrity_size();
	}
	return packet_size;
}

span ssh_bp_encoder::get(std::size_t size) {
	data_ = out_.get(calculate_size(size));
	SPSSH_ASSERT(!data_.empty(), "allocation failed");
	used_ = header_size;
	// return the range for payload
	return span{data_.data()+header_size, size};
}

void ssh_bp_encoder::commit(std::size_t size) {
	used_ += size;
}

span ssh_bp_encoder::expand(std::size_t new_size, std::size_t used) {
	data_ = out_.expand(calculate_size(new_size), header_size + used);
	SPSSH_ASSERT(!data_.empty(), "allocation failed");
	// return the range for payload
	return span{data_.data()+header_size, new_size};
}

std::size_t ssh_bp_encoder::max_size() const {
	return out_.max_size()-calculate_size(0);
}

std::size ssh_bp_encoder::aead_encrypt(aead_cipher& cip, const_span data, span out) {
	// authenticate the packet length as we don't done encrypt it
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

	return cip.tag_size();
}

std::size ssh_bp_encoder::encrypt_with_mac(const_span data, span out) {
	// mac = MAC(key, sequence_number || unencrypted_packet)
	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(stream_.packet_sequence, seq_buf);
	stream_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	stream_.mac->process(data);
	// add mac at the end
	stream_.mac->result(out.subspan(data.size()));
	// encrypt the packet
	stream_.cipher->process(data, out.subspan(0, data.size()));

	return stream_.mac->size();
}

// returns only the size of integrity added
std::size ssh_bp_encoder::encrypt(const_span data, span out) {
	std::size res = 0;
	if(stream_.cipher) {
		if(stream_.is_aead()) {
			res = aead_encrypt(static_cast<aead_cipher&>(*stream_), data, out);
		} else {
			SPSSH_ASSERT(stream_.mac);
			res = encrypt_with_mac(data, out);
		}
	}
	return res;
}

void ssh_bp_encoder::send_packet() {
	// binary packet cannot have empty payload
	if(used_) {
		SPSSH_ASSERT(!data_.empty(), "invalid finalize call");
		ssh_bf_writer p{data_};

		// calculate padding again based on the actual payload size committed to
		std::size_t padding_size = calculate_min_padding(header_size + used_);

		p.add_uint32(1 + used_ + padding_size); // padding_length + payload + padding
		p.add_uint8(padding_size);
		p.jump_over(used_); // just jump over the payload bytes as those have been written there already
		p.add_random_range(padding_size);

		std::size_t commit_size = p.used_size();
		// encrypt and add integrity protection
		commit_size += encrypt(p.used_span(), p.total_span());

		out_.commit(commit_size);

		// incremented for every packet and let wrap around
		++stream_.packet_sequence;
		used_ = 0;
	}
}


ssh_bp_decoder::ssh_bp_decoder(ssh_config const& config, stream_in_crypto& stream, in_buffer& in, packet_decode_header header)
: config_(config)
, stream_(stream)
, in_(in)
, data_(in.get())
, packet_multiplier_(block_size(stream_))
, integrity_size_()
{
	// t: move the integrity size to stream_in_crypto
	if(stream_.cipher) {
		if(stream_.cipher->is_aead()) {
			integrity_size_ = static_cast<aead_cipher const&>(*stream_.cipher).tag_size();
		} else {
			SPSSH_ASSERT(stream_.mac);
			integrity_size_ = stream_.mac->size();
		}
	}
}

bool ssh_bp_decoder::decode_header() {
	if(data_.size() < packet_multiplier_) {
		return false;
	}
	// check if the  packet length is encrypted or not
	if(stream_.cipher && !stream_.cipher->is_aead()) {
		// decrypt just the first block to get the length
		auto block_span = data_.subspan(0, packet_multiplier_);
		stream_.cipher->process(block_span, block_span);
	}
	stream_.packet_header.packet_size = ntou32(data_.data());
	return true;
}

bool ssh_bp_decoder::aead_decrypt(aead_cipher& cip, const_span data, span out) {
	// first handle the non-encrypted authenticated data
	cip.process_auth(data.subspan(0, packet_lenght_size));
	data = data.subspan(packet_lenght_size);
	// decrypt the data
	cip.process(data, out);

	// get the tag
	std::vector<std::byte> tag(integrity_size_);
	cip.tag(tag);

	// check the tag matches
	if(std::memcmp(tag.data(), data.data() + stream_.packet_header.packet_size, integrity_size_) != 0) {
		return false;
	}

	std::uint8_t padding = std::to_integer<std::uint8_t>(out_.data());
	payload_ = span{out.subspan(padding_size, stream_.packet_header.packet_size - padding_size - padding)};

	return true;
}

bool ssh_bp_decoder::decrypt_with_mac(const_span data, span out) {
	// here the first block is already decrypted so that we found the packet_length
	std::uint8_t padding = std::to_integer<std::uint8_t>(data.data() + packet_lenght_size);
	// if we are not doing decryption in place, copy the first block to out
	if(data.data() != out.data()) {
		std::memcpy(out.data(), data.data(), packet_multiplier_);
	}
	data = data.subspan(packet_multiplier_);

	std::size_t decrypt_size = stream_.packet_header.packet_size - packet_multiplier_ + packet_lenght_size;
	stream_.cipher.process(data.subspan(0, decrypt_size), out.subspan(packet_multiplier_, decrypt_size));

	std::byte seq_buf[4];
	// convert the packet sequence to binary and process for mac
	u32ton(stream_.packet_sequence, seq_buf);

	stream_.mac->process(span{seq_buf, 4});
	// process the packet for mac
	stream_.mac->process(out.subspan(packet_lenght_size, stream_.packet_header.packet_size));

	// get the tag
	std::vector<std::byte> mac(integrity_size_);
	stream_.mac->result(mac);

	// check the tag matches
	if(std::memcmp(mac.data(), out.data() + stream_.packet_header.packet_size + packet_lenght_size, integrity_size_) != 0) {
		return false;
	}

	payload_ = span{out.subspan(header_size, stream_.packet_header.packet_size - padding_size - padding)};

	return true;
}

bool ssh_bp_decoder::decode() {
	if(data_.size() < packet_lenght_size + stream_.packet_header.packet_size + integrity_size_) {
		return false;
	}

	bool ret = true;
	// are we encrypted?
	if(stream_.cipher) {
		if(stream_.cipher->is_aead()) {
			ret = aead_decrypt(static_cast<aead_cipher&>(*stream_), data_, data_);
		} else {
			ret = decrypt_with_mac(data_, data_);
		}
	} else {
		std::uint8_t padding = std::to_integer<std::uint8_t>(data.data() + packet_lenght_size);
		payload_ = span{data_.subspan(header_size, stream_.packet_header.packet_size - padding_size - padding)};
	}

	// incremented for every packet and let wrap around
	++stream_.packet_sequence;

	return ret;
}

const_span ssh_bp_decoder::payload() const {
	return payload_;
}

}

