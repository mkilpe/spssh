#include "stream_crypto.hpp"

#include "ssh_config.hpp"
#include "ssh_binary_format.hpp"
#include "types.hpp"

namespace securepath::ssh {

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
			SPSSH_ASSERT(stream_.mac, "MAC object not set");
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


}

