#ifndef SPSSH_CORE_KEX_COMMON_HEADER
#define SPSSH_CORE_KEX_COMMON_HEADER

#include "ssh/core/kex.hpp"
#include "ssh/core/ssh_config.hpp"
#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh {

hash_type deduce_hash_type(kex_type t) {
	using enum kex_type;
	switch(t) {
		case dh_group14_sha256: [[fallthrough]];
		case curve25519_sha256: [[fallthrough]];
		case libssh_curve25519_sha256: [[fallthrough]];
		case ecdh_sha2_nistp256:
			return hash_type::sha2_256;
		case dh_group16_sha512:
			return hash_type::sha2_512;
		case unknown:
			return hash_type::unknown;
	}
	return hash_type::unknown;
}

key_exchange_type deduce_exchange_type(kex_type t) {
	using enum kex_type;
	switch(t) {
		case curve25519_sha256:        return key_exchange_type::X25519;
		case libssh_curve25519_sha256: return key_exchange_type::X25519;
		case dh_group14_sha256:        return key_exchange_type::dh_group14;
		case dh_group16_sha512:        return key_exchange_type::dh_group16;
		case ecdh_sha2_nistp256:       return key_exchange_type::unknown; //this is not implemented yet
		case unknown:                  return key_exchange_type::unknown;
	}
	return key_exchange_type::unknown;
}

struct kex_common : public kex {
	kex_common(kex_context kex_c, kex_type ktype)
	: context_(kex_c)
	, kex_type_(ktype)
	, hash_type_(deduce_hash_type(ktype))
	, exchange_(context_.ccontext().construct_key_exchange(key_exchange_data_type{deduce_exchange_type(ktype)}, context_.call_context()))
	{
	}

	kex_type type() const override {
		return kex_type_;
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

		string         V_C, client's identification string (CR and LF excluded)
		string         V_S, server's identification string (CR and LF excluded)
		string         I_C, payload of the client's SSH_MSG_KEXINIT
		string         I_S, payload of the server's SSH_MSG_KEXINIT
		string         K_S, server's public host key
		string/mpint   Q_C, client's ephemeral public key octet string / mpint
		string/mpint   Q_S, server's ephemeral public key octet string / mpint
		mpint          K,   shared secret

		The 32 bytes of secret X are converted into K by interpreting the octets as an unsigned fixed-length integer encoded in network byte order.
		[RFC8731]
	*/
	template<typename EphKeyType>
	byte_vector calculate_exchange_hash(const_span host_key, EphKeyType remote_eph_key, const_span secret) {
		auto hash = context_.ccontext().construct_hash(hash_type_, context_.call_context());
		if(!hash) {
			context_.logger().log(logger::debug_trace, "Could not construct hash");
			return {};
		}

		hash_binout bo(*hash);
		ssh_bf_binout_writer w(bo);

		kex_init_data const& kinit = context_.init_data();
		transport_side side = context_.config().side;

		hash_ident_string(w, side == transport_side::client ? kinit.local_ver : kinit.remote_ver);
		hash_ident_string(w, side == transport_side::client ? kinit.remote_ver : kinit.local_ver);
		w.write(to_string_view(side == transport_side::client ? kinit.local_kexinit : kinit.remote_kexinit));
		w.write(to_string_view(side == transport_side::client ? kinit.remote_kexinit : kinit.local_kexinit));
		w.write(to_string_view(host_key));
		// see if the ephemeral key type is mpint, otherwise threat it as string
		if constexpr (std::is_same_v<EphKeyType, const_mpint_span>) {
			w.write(side == transport_side::client ? to_mpint(exchange_->public_key(), remote_eph_key.sign) : remote_eph_key);
			w.write(side == transport_side::client ? remote_eph_key : to_mpint(exchange_->public_key(), remote_eph_key.sign));
		} else {
			w.write(side == transport_side::client ? to_string_view(exchange_->public_key()) : remote_eph_key);
			w.write(side == transport_side::client ? remote_eph_key : to_string_view(exchange_->public_key()));
		}
		w.write(const_mpint_span{secret});

		return hash->digest();
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
		auto hash = context_.ccontext().construct_hash(hash_type_, context_.call_context());
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
	kex_type kex_type_{kex_type::unknown};
	hash_type hash_type_{hash_type::unknown};
	kex_state state_{kex_state::none};
	crypto_configuration conf_;
	std::unique_ptr<key_exchange> exchange_;

	const_span session_id_;
	byte_vector exchange_hash_;
	byte_vector secret_;
	byte_vector server_host_key_;
};

}

#endif