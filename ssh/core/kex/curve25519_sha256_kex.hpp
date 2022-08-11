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
	, x25519_(context_.ccontext().construct_key_exchange(key_exchange_data_type{key_exchange_type::X25519}, context_.call_context()))
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

	template<typename... Args>
	void set_error(ssh_error_code code, std::string_view msg, Args&&... args) {
		err_message_ = context_.logger().format(msg, std::forward<Args>(args)...);
		error_ = code;
		context_.logger().log_line(logger::error, err_message_);
		set_state(kex_state::error);
	}

	void set_crypto_configuration(crypto_configuration conf) override {
		conf_ = conf;
	}

	void hash_ident_string(ssh_bf_binout_writer& h, ssh_version const& v) const {
		std::string vs = "SSH-" + v.ssh + "-" + v.software;
		if(!v.comment.empty()) {
			vs += " " + v.comment;
		}
		h.write(vs);
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
		w.write(to_string_view(side == transport_side::client ? kinit.local_kexinit : kinit.remote_kexinit));
		w.write(to_string_view(side == transport_side::client ? kinit.remote_kexinit : kinit.local_kexinit));
		w.write(to_string_view(host_key));
		w.write(side == transport_side::client ? to_string_view(x25519_->public_key()) : remote_eph_key);
		w.write(side == transport_side::client ? remote_eph_key : to_string_view(x25519_->public_key()));
		w.write(const_mpint_span{secret});

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

	/*
		K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
		K2 = HASH(K || H || K1)
		K3 = HASH(K || H || K1 || K2)
		...
		key = K1 || K2 || K3 || ...
	*/
	byte_vector derive_crypto_material(hash& h, std::size_t size, char type) {
		hash_binout hbout(h);
		ssh_bf_binout_writer w(hbout);

		byte_vector res;
		w.write(const_mpint_span{secret_});
		w.write(exchange_hash_);
		w.write(std::uint8_t(type));
		w.write(session_id_);
		res = h.digest();

		while(res.size() < size) {
			w.write(const_mpint_span{secret_});
			w.write(exchange_hash_);
			w.write(res);
			auto d = h.digest();
			res.insert(res.end(), d.begin(), d.end());
		}

		res.resize(size);
		return res;
	}

	void set_data(byte_vector exhash, byte_vector secret, byte_vector host_key) {
		exchange_hash_ = std::move(exhash);
		secret_ = std::move(secret);
		server_host_key_ = std::move(host_key);

		// if this is first kex, use the exchange hash as session id
		if(context_.init_data().session_id.empty()) {
			session_id_ = exchange_hash_;
		} else {
			session_id_ = context_.init_data().session_id;
		}
	}

	const_span session_id() const override {
		return session_id_;
	}

	ssh_public_key server_host_key() const override {
		return load_ssh_public_key(server_host_key_, context_.ccontext(), context_.call_context());
	}

protected:
	kex_context context_;
	kex_state state_{kex_state::none};
	crypto_configuration conf_;
	std::unique_ptr<key_exchange> x25519_;

	const_span session_id_;
	byte_vector exchange_hash_;
	byte_vector secret_;
	byte_vector server_host_key_;
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
		set_error(ssh_key_exchange_failed, "Failed to initiate kex");
		return kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		if(state_ != kex_state::inprogress) {
			set_error(ssh_key_exchange_failed, "Invalid state");
			return kex_state::error;
		}

		if(type == ssh_packet_type(ssh_kex_ecdh_reply)) {
			ser::kex_ecdh_reply::load packet(ser::match_type_t, payload);
			if(packet) {
				auto & [host_key, server_eph_key, sig] = packet;

				auto secret = x25519_->agree(to_span(server_eph_key));

				if(is_zero(secret)) {
					set_error(ssh_key_exchange_failed, "Invalid shared secret");
					return kex_state::error;
				}

				auto host_key_span = to_span(host_key);
				auto hash = calculate_exchange_hash(host_key_span, server_eph_key, secret);
				if(hash.empty()) {
					set_error(ssh_key_exchange_failed, "Failed to calculate exchange hash");
					return kex_state::error;
				}

				ssh_public_key hkey = load_ssh_public_key(host_key_span, context_.ccontext(), context_.call_context());
				if(!hkey.valid()) {
					set_error(ssh_key_exchange_failed, "Failed to load server host key");
					return kex_state::error;
				}

				if(!hkey.verify(hash, to_span(sig))) {
					set_error(ssh_key_exchange_failed, "Failed to verify signature");
					return kex_state::error;
				}

				set_data(std::move(hash), std::move(secret), byte_vector(host_key_span.begin(), host_key_span.end()));
				return set_state(kex_state::succeeded);
			} else {
				set_error(ssh_key_exchange_failed, "Invalid kex packet");
			}
		} else {
			set_error(ssh_key_exchange_failed, "Wrong kex packet [type={}]", type);
		}
		return kex_state::error;
	}

};

struct curve25519_sha256_kex_server : public curve25519_sha256_kex_base {
	curve25519_sha256_kex_server(kex_context kex_c)
	: curve25519_sha256_kex_base(kex_c)
	{
		context_.logger().log(logger::debug_trace, "constructing curve25519_sha256_kex_server");
	}

	kex_state initiate() override {
		if(x25519_) {
			return set_state(kex_state::inprogress);
		}
		set_error(ssh_key_exchange_failed, "Failed to construct kex");
		return kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		if(state_ != kex_state::inprogress) {
			set_error(ssh_key_exchange_failed, "Invalid state");
			return kex_state::error;
		}
		if(type == ssh_packet_type(ssh_kex_ecdh_init)) {
			ser::kex_ecdh_init::load packet(ser::match_type_t, payload);
			if(packet) {
				auto & [client_key] = packet;

				auto secret = x25519_->agree(to_span(client_key));

				if(is_zero(secret)) {
					set_error(ssh_key_exchange_failed, "Invalid shared secret");
					return kex_state::error;
				}

				return send_reply(client_key, std::move(secret));
			} else {
				set_error(ssh_key_exchange_failed, "Invalid kex packet");
			}
		} else {
			set_error(ssh_key_exchange_failed, "Wrong kex packet [type={}]", type);
		}
		return kex_state::error;
	}

	kex_state send_reply(std::string_view client_key, byte_vector secret) {
		auto it = std::find_if(context_.config().private_keys.begin(),
							context_.config().private_keys.end(),
							[&](auto&& v) { return v.key.type() == conf_.host_key; });

		if(it == context_.config().private_keys.end()) {
			set_error(ssh_key_exchange_failed, "Failed to find suitable host key");
			return kex_state::error;
		}

		auto hash = calculate_exchange_hash(it->ser_pubkey, client_key, secret);
		if(hash.empty()) {
			set_error(ssh_key_exchange_failed, "Failed to calculate exchange hash");
			return kex_state::error;
		}

		byte_vector sig = it->key.sign(hash);
		if(sig.empty()) {
			set_error(ssh_key_exchange_failed, "Failed to sign exchange hash");
			return kex_state::error;
		}

		if(!context_.send_packet<ser::kex_ecdh_reply>(
			to_string_view(it->ser_pubkey),
			to_string_view(x25519_->public_key()),
			to_string_view(sig)))
		{
			set_error(ssh_key_exchange_failed, "Failed to create reply packet");
			return kex_state::error;
		}

		set_data(std::move(hash), std::move(secret), it->ser_pubkey);
		return set_state(kex_state::succeeded);
	}

};

}

#endif