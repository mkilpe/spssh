#ifndef SP_SHH_BINARY_PACKET_HEADER
#define SP_SHH_BINARY_PACKET_HEADER

#include "buffers.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/compression.hpp"
#include "ssh/crypto/mac.hpp"

#include <cstring>
#include <memory>
#include <vector>

namespace securepath::ssh {

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

	// this is mac->size() or aead_cipher->tag_size() when we are encrypting, otherwise 0
	std::uint32_t integrity_size{};
};

/// status of incoming packet that is currently being handled
enum class in_packet_status {
	waiting_header, // we have no data or not enough for first block
	waiting_data,   // we have decrypted first block (or we use aead) and know the packet length
	data_ready      // we have decrypted whole packet and ready to process it
};

struct in_packet_info {
	in_packet_status status{in_packet_status::waiting_header};
	std::size_t packet_size{}; // size of the whole packet, this is available after decrypting the header
	std::size_t data_size{};   // size of the transport payload, this is available after decrypting whole packet
	span payload{};            // current decrypted payload to be handled

	void clear() {
		status = in_packet_status::waiting_header;
		packet_size = 0;
		data_size = 0;
		payload = {};
	}
};

struct stream_in_crypto : public stream_crypto {
	in_packet_info current_packet;
	// buffer for calculating tag, should be always integrity_size
	std::vector<std::byte> tag_buffer;
};

struct out_packet_info {
	// size of the whole packet with padding and integrity
	std::size_t size{};
	// size of the payload
	std::size_t payload_size{};
	// size of the random padding
	std::size_t padding_size{};
};

struct stream_out_crypto : public stream_crypto {
	// buffer for output data
	std::vector<std::byte> buffer;
};

class ssh_binary_packet {
public:
	ssh_binary_packet(ssh_config const& config, logger& logger);

	ssh_error_code error() const;
	std::string error_message() const;

	void set_error(ssh_error_code code, std::string_view message);

public: //input
	bool set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac);
	bool try_decode_header(span in_data);
	span decrypt_packet(const_span in_data, span out_data);
	span decrypt_aead(aead_cipher& cip, const_span data, span out);
	span decrypt_with_mac(const_span data, span out);

public: //output
	out_packet_info out_packet_size(std::size_t data_size) const;
	std::size_t minimum_padding(std::size_t header_payload_size) const;

	void aead_encrypt(aead_cipher& cip, const_span data, span out);
	void encrypt_with_mac(const_span data, span out);
	void encrypt_packet(const_span data, span out);

	bool create_out_packet(out_packet_info const&, const_span data, span out);
	bool create_out_packet_in_place(out_packet_info const&, span data);
private:
	bool resize_out_buffer(std::size_t);
	void shrink_out_buffer();

protected:
	ssh_config const& config_;
	logger& logger_;

	ssh_error_code error_{};
	std::string error_msg_;

	stream_in_crypto  crypto_in_;
	stream_out_crypto crypto_out_;
};


}

#endif
