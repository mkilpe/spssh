#ifndef SPSSH_CORE_KEX_CURVE25519_SHA256_HEADER
#define SPSSH_CORE_KEX_CURVE25519_SHA256_HEADER

#include "ecdh.hpp"
#include "ssh/core/kex.hpp"
#include "ssh/core/ssh_config.hpp"
#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh {

struct curve25519_sha256_kex_base : public kex {
	curve25519_sha256_kex_base(kex_context kex_c)
	: context_(kex_c)
	, x25519_(context_.ccontext().construct_key_exchange(key_exchange_type::X25519, context_.call_context()))
	{
	}

	kex_type type() const override {
		return kex_type::curve25519_sha256;
	}

	kex_state state() const override {
		return state_;
	}

	kex_state set_state(kex_state s) {
		SPSSH_ASSERT(state_ == kex_state::none || state_ == kex_state::inprogress, "invalid state change");
		state_ = s;
		return s;
	}

	void set_crypto_configuration(crypto_configuration conf) override {
		conf_ = conf;
	}

	void hash_ident_string(ssh_bf_binout_writer& h, ssh_version const& v) const {
		h.write("SSH-");
		h.write(v.ssh);
		h.write("-");
		h.write(v.software);
		if(!v.comment.empty()) {
			h.write(" ");
			h.write(v.comment);
		}
	}

	/*
		The exchange hash H is computed as the hash of the concatenation of
		the following. [RFC5656]

		string   V_C, client's identification string (CR and LF excluded)
		string   V_S, server's identification string (CR and LF excluded)
		string   I_C, payload of the client's SSH_MSG_KEXINIT
		string   I_S, payload of the server's SSH_MSG_KEXINIT
		string   K_S, server's public host key
		string   Q_C, client's ephemeral public key octet string
		string   Q_S, server's ephemeral public key octet string
		mpint    K,   shared secret

		The 32 bytes of secret X are converted into K by interpreting the octets as an unsigned fixed-length integer encoded in network byte order.
		[RFC8731]
	*/
	byte_vector calculate_exchange_hash(const_span host_key, std::string_view remote_eph_key, const_span secret) {
		auto sha256 = context_.ccontext().construct_hash(hash_type::sha2_256, context_.call_context());
		if(!sha256) {
			context_.logger().log(logger::debug_trace, "Could not construct hash");
			return {};
		}

		hash_binout bo(*sha256);
		ssh_bf_binout_writer w(bo);

		kex_init_data const& kinit = context_.init_data();
		transport_side side = context_.config().side;

		hash_ident_string(w, side == transport_side::client ? kinit.local_ver : kinit.remote_ver);
		hash_ident_string(w, side == transport_side::client ? kinit.remote_ver : kinit.local_ver);
		w.write(side == transport_side::client ? kinit.local_kexinit : kinit.remote_kexinit);
		w.write(side == transport_side::client ? kinit.remote_kexinit : kinit.local_kexinit);
		w.write(host_key);
		w.write(side == transport_side::client ? to_span(remote_eph_key) : x25519_->public_key());
		w.write(side == transport_side::client ? x25519_->public_key() : to_span(remote_eph_key));
		w.write(to_umpint(secret));

		return sha256->digest();
	}

	std::optional<crypto_pair> construct_in_crypto_pair() override {
		if(context_.config().side == transport_side::client) {
			return construct_crypto_pair(cipher_dir::decrypt, conf_.in, "BDF");
		} else {
			return construct_crypto_pair(cipher_dir::decrypt, conf_.in, "ACE");
		}
	}

	std::optional<crypto_pair> construct_out_crypto_pair() override {
		if(context_.config().side == transport_side::client) {
			return construct_crypto_pair(cipher_dir::encrypt, conf_.out, "ACE");
		} else {
			return construct_crypto_pair(cipher_dir::encrypt, conf_.out, "BDF");
		}
	}

	std::optional<crypto_pair> construct_crypto_pair(cipher_dir dir, crypto_configuration::type const& conf, char const* chars) {
		std::optional<crypto_pair> res;
		auto hash = context_.ccontext().construct_hash(hash_type::sha2_256, context_.call_context());
		if(hash) {
			// derive iv
			auto iv = derive_crypto_material(*hash, cipher_iv_size(conf.cipher), chars[0]);
			// derive encryption key
			auto key = derive_crypto_material(*hash, cipher_key_size(conf.cipher), chars[1]);
			auto cipher = context_.ccontext().construct_cipher(conf.cipher, dir, key, iv, context_.call_context());
			if(!cipher) {
				return std::nullopt;
			}
			res.emplace(std::move(cipher));
			if(!res->cipher->is_aead()) {
				// derive integrity key
				auto mac_key = derive_crypto_material(*hash, mac_key_size(conf.mac), chars[2]);
				auto mac = context_.ccontext().construct_mac(conf.mac, mac_key, context_.call_context());
				if(!mac) {
					return std::nullopt;
				}
				res->mac = std::move(mac);
			}
		}
		return res;
	}

	byte_vector derive_crypto_material(hash& h, std::size_t size, char type) {
		return {};
	}

	void set_exchange_hash_and_secret(byte_vector exhash, byte_vector secret) {
		exchange_hash_ = std::move(exhash);
		secret_ = std::move(secret);
	}

protected:
	kex_context context_;
	kex_state state_{kex_state::none};
	crypto_configuration conf_;
	std::unique_ptr<key_exchange> x25519_;

	byte_vector exchange_hash_;
	byte_vector secret_;
};

struct curve25519_sha256_kex_client : public curve25519_sha256_kex_base {
	curve25519_sha256_kex_client(kex_context kex_c)
	: curve25519_sha256_kex_base(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex_client");
	}

	kex_state initiate() override {
		if(x25519_) {
			if(context_.send_packet<ser::kex_ecdh_init>(to_string_view(x25519_->public_key()))) {
				return set_state(kex_state::inprogress);
			}
		}
		return set_state(kex_state::error);
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		if(type == ssh_packet_type(ssh_kex_ecdh_reply)) {
			ser::kex_ecdh_reply::load packet(ser::match_type_t, payload);
			if(packet) {
				auto & [host_key, server_eph_key, sig] = packet;

				auto secret = x25519_->agree(to_span(server_eph_key));

				// check the secret is not all zeroes (by taking always same time)
				std::byte combined{0};
				for(auto& v : secret) {
					combined |= v;
				}
				if(combined == std::byte{0}) {
					context_.logger().log(logger::debug_trace, "invalid shared secret");
					return set_state(kex_state::error);
				}

				auto hash = calculate_exchange_hash(to_span(host_key), server_eph_key, secret);
				if(hash.empty()) {
					context_.logger().log(logger::debug_trace, "Failed to calcualte exchange hash");
					return set_state(kex_state::error);
				}

				ssh_public_key hkey = load_ssh_public_key(to_span(host_key), context_.ccontext(), context_.call_context());
				if(!hkey.valid()) {
					context_.logger().log(logger::debug_trace, "Failed to load server host key");
					return set_state(kex_state::error);
				}

				if(!hkey.verify(hash, to_span(sig))) {
					context_.logger().log(logger::debug_trace, "Failed to verify signature");
					return set_state(kex_state::error);
				}

				set_exchange_hash_and_secret(std::move(hash), std::move(secret));
				return set_state(kex_state::succeeded);
			}
		}
		return set_state(kex_state::error);
	}

};

struct curve25519_sha256_kex_server : public curve25519_sha256_kex_base {
	curve25519_sha256_kex_server(kex_context kex_c)
	: curve25519_sha256_kex_base(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex_server");
	}

	kex_state initiate() override {
		return set_state(x25519_ ? kex_state::inprogress : kex_state::error);
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		if(type == ssh_packet_type(ssh_kex_ecdh_init)) {
			ser::kex_ecdh_init::load packet(ser::match_type_t, payload);
			if(packet) {
				auto & [client_key] = packet;

				auto secret = x25519_->agree(to_span(client_key));

				// check the secret is not all zeroes (by taking always same time)
				std::byte combined{0};
				for(auto& v : secret) {
					combined |= v;
				}
				if(combined == std::byte{0}) {
					context_.logger().log(logger::debug_trace, "invalid shared secret");
					return set_state(kex_state::error);
				}

				return send_reply(client_key, std::move(secret));
			}
		}
		return set_state(kex_state::error);
	}

	kex_state send_reply(std::string_view client_key, byte_vector secret) {
		auto it = std::find_if(context_.config().private_keys.begin(),
							context_.config().private_keys.end(),
							[&](auto&& v) { return v.key.type() == conf_.host_key; });

		if(it == context_.config().private_keys.end()) {
			context_.logger().log(logger::debug_trace, "Failed to find suitable host key");
			return set_state(kex_state::error);
		}

		auto hash = calculate_exchange_hash(it->ser_pubkey, client_key, secret);
		if(hash.empty()) {
			context_.logger().log(logger::debug_trace, "Failed to calcualte exchange hash");
			return set_state(kex_state::error);
		}

		byte_vector sig = it->key.sign(hash);
		if(sig.empty()) {
			context_.logger().log(logger::debug_trace, "Failed to sign exchange hash");
			return set_state(kex_state::error);
		}

		if(!context_.send_packet<ser::kex_ecdh_reply>(
			to_string_view(it->ser_pubkey),
			to_string_view(x25519_->public_key()),
			to_string_view(sig)))
		{
			return set_state(kex_state::error);
		}

		set_exchange_hash_and_secret(std::move(hash), std::move(secret));
		return set_state(kex_state::succeeded);
	}

};

}

#endif