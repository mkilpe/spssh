#ifndef SP_SHH_STREAM_CRYPTO_HEADER
#define SP_SHH_STREAM_CRYPTO_HEADER

#include "buffers.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/compression.hpp"

#include <cstring>
#include <memory>

namespace securepath::ssh {

class ssh_config;

/// Necessary crypto components and buffers for single stream (i.e. one direction communication)
struct stream_crypto {
	/// sequence number of packet, incremented after every binary protocol packet
	std::uint32_t packet_sequence{};

	std::unique_ptr<compression> compress;
	std::unique_ptr<ssh::cipher> cipher;
	// this is only used if !cipher->is_aead()
	std::unique_ptr<ssh::mac> mac;
};

struct packet_decode_header {
	std::size_t packet_size{};

	bool is_valid() const { return packet_size; };
};

struct stream_in_crypto : public stream_crypto {
	packet_decode_header packet_header;
};

struct stream_out_crypto : public stream_crypto {
	//stream_out_buffer buffer;
};


class ssh_bp_encoder final : public out_buffer {
public:
	ssh_bp_encoder(ssh_config const& config, stream_out_crypto& stream, out_buffer& out);

	span get(std::size_t size) override;
	span expand(std::size_t new_size, std::size_t used) override;
	void commit(std::size_t size) override;
	std::size_t max_size() const override;

	/// create binary packet and push it to the underlying buffer for sending
	void send_packet();

private:
	std::size_t calculate_size(std::size_t) const;
	std::size_t calculate_min_padding(std::size_t) const;
	std::size encrypt(const_span data, span out);
	std::size aead_encrypt(aead_cipher& cip, const_span data, span out);
	std::size encrypt_with_mac(const_span data, span out);

private:
	ssh_config const& config_;
	stream_out_crypto& stream_;
	out_buffer& out_;
	std::size_t packet_multiplier_;
	span data_;
	std::size_t used_{};
};


class ssh_bp_decoder {
public:
	ssh_bp_decoder(ssh_config const& config, stream_in_crypto& stream, in_buffer& in);

	bool decode_header();
	bool decode();

	const_span payload() const;

private:
	ssh_config const& config_;
	stream_in_crypto& stream_;
	in_buffer& in_;
	const_span data_;
	std::size_t packet_multiplier_;
};

}

#endif
