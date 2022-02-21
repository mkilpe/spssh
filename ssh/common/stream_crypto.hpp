#ifndef SP_SHH_STREAM_CRYPTO_HEADER
#define SP_SHH_STREAM_CRYPTO_HEADER

#include "buffers.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/compression.hpp"
#include "ssh/crypto/mac.hpp"

#include <cstring>
#include <memory>
#include <vector>

namespace securepath::ssh {

std::size_t const packet_lenght_size = 4;
std::size_t const padding_size = 1;
// header size = packet_length 4 bytes + padding length 1 byte
std::size_t const packet_header_size = packet_lenght_size + padding_size;
std::size_t const maximum_padding_size = 255;

// minimum "block" size, the length of header+payload must be multiple of the "block" size (even for stream ciphers).
std::size_t const minimum_block_size = 8;

// at least 4 bytes of padding is always required per SSH specification
std::size_t const minimum_padding_size = 4;

class ssh_config;

/// Necessary crypto components and buffers for single stream (i.e. one direction communication)
struct stream_crypto {
	/// sequence number of packet, incremented after every binary protocol packet
	std::uint32_t packet_sequence{};
	std::uint32_t block_size{minimum_block_size};

	std::unique_ptr<compression> compress;
	std::unique_ptr<ssh::cipher> cipher;
	// this is only used if !cipher->is_aead()
	std::unique_ptr<ssh::mac> mac;

	// this is mac->size() or aead_cipher->tag_size() when we are encrypting
	std::uint32_t integrity_size{};
};

/// status of incoming packet that is currently being handled
enum class packet_status {
	waiting_header, // we have no data or not enough for first block
	waiting_data,   // we have decrypted first block (or we use aead) and know the packet length
	data_ready      // we have decrypted whole packet and ready to process it
};

struct packet_info {
	packet_status status{packet_status::waiting_header};
	std::size_t packet_size{}; // size of the whole packet, this is available after decrypting the header
	std::size_t data_size{};   // size of the transport payload, this is available after decrypting whole packet
	span payload{};            // current decrypted payload to be handled

	void clear() {
		status = packet_status::waiting_header;
		packet_size = 0;
		data_size = 0;
		payload = {};
	}
};

struct stream_in_crypto : public stream_crypto {
	packet_info current_packet;
	// buffer for calculating tag, should be always integrity_size
	std::vector<std::byte> tag_buffer;
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
	std::size_t encrypt(const_span data, span out);
	std::size_t aead_encrypt(aead_cipher& cip, const_span data, span out);
	std::size_t encrypt_with_mac(const_span data, span out);

private:
	ssh_config const& config_;
	stream_out_crypto& stream_;
	out_buffer& out_;
	std::size_t packet_multiplier_;
	span data_;
	std::size_t used_{};
};

}

#endif
