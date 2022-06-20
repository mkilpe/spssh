#include "private_key_op.hpp"

#include "ssh/core/ssh_private_key.hpp"
#include "ssh/core/ssh_binary_util.hpp"

#include <limits>

namespace securepath::ssh {

std::string to_ecdsa_signature_blob(const_span s) {
	std::string res;
	string_binout out(res);
	ssh_bf_binout_writer w(out);

	w.write(const_mpint_span{safe_subspan(s, 0, s.size()/2)});
	w.write(const_mpint_span{safe_subspan(s, s.size()/2, s.size()/2)});

	return res;
}

bool ser_ed25519_private_key(ssh_bf_binout_writer& w, private_key const& key, std::string_view comment) {
	ed25519_private_key_data data;
	return key.fill_data(data)
		&& data.pubkey
		&& w.write(to_string_view(*data.pubkey))
		&& w.write(std::string(to_string_view(data.privkey)) + std::string(to_string_view(*data.pubkey)))
		&& w.write(comment);
}

bool ser_rsa_private_key(ssh_bf_binout_writer& w, private_key const& key, std::string_view comment) {
	rsa_private_key_data data;
	return key.fill_data(data)
		&& w.write(data.n)
		&& w.write(data.e)
		&& w.write(data.d)
		&& w.write(data.iqmp)
		&& w.write(data.p)
		&& w.write(data.q)
		&& w.write(comment);
}

bool ser_ecdsa_private_key(ssh_bf_binout_writer& w, private_key const& key, std::string_view comment) {
	ecdsa_private_key_data data{key_type::ecdsa_sha2_nistp256};
	return key.fill_data(data)
		&& w.write(to_curve_name(data.ecdsa_type))
		&& w.write(to_string_view(data.ecc_point))
		&& w.write(data.privkey)
		&& w.write(comment);
}

ssh_private_key load_raw_ed25519_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ed25519 private key");
	std::string_view pubkey;
	std::string_view privkey;
	std::string_view comment;
	if(r.read(pubkey) && r.read(privkey) && r.read(comment)) {
		if(pubkey.size() == ed25519_key_size && privkey.size() == ed25519_key_size || privkey.size() == 2*ed25519_key_size) {
			auto pub_bytes = to_span(pubkey);
			// openssh has 64 bytes in the private key part, apparently the public key is repeated in the latter 32 bytes
			auto priv_bytes = to_span(privkey).subspan(0, ed25519_key_size);

			ed25519_private_key_data data{
				const_span(priv_bytes.data(), priv_bytes.size()),
				const_span(pub_bytes.data(), pub_bytes.size())
			};
			return ssh_private_key(crypto.construct_private_key(data, call), comment);
		} else {
			call.log.log(logger::debug_trace, "ed25519 public or private key size not correct");
		}
	} else {
		call.log.log(logger::debug_trace, "Failed to read ed25519 private key");
	}
	return {};
}

ssh_private_key load_raw_rsa_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading rsa private key");
	std::string_view n, e, d, iqmp, p, q;
	std::string_view comment;
	if(r.read(n) && r.read(e) && r.read(d) && r.read(iqmp) && r.read(p) && r.read(q) && r.read(comment)) {
		rsa_private_key_data data{to_umpint(e), to_umpint(n), to_umpint(d),	to_umpint(p), to_umpint(q), to_umpint(iqmp)};
		return ssh_private_key(crypto.construct_private_key(data, call), comment);
	} else {
		call.log.log(logger::debug_trace, "Failed to read rsa private key");
	}
	return {};
}

ssh_private_key load_raw_ecdsa_private_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ecdsa private key");
	std::string_view curve;
	std::string_view ecc_point; // public key
	std::string_view privkey;
	std::string_view comment;
	if(r.read(curve) && r.read(ecc_point) && r.read(privkey) && r.read(comment)) {
		if("ecdsa-sha2-" + std::string(curve) == type) {
			ecdsa_private_key_data data{key_type::ecdsa_sha2_nistp256, to_span(ecc_point), to_umpint(privkey)};
			return ssh_private_key(crypto.construct_private_key(data, call), comment);
		} else {
			call.log.log(logger::debug_trace, "Invalid ecdsa private key");
		}
	} else {
		call.log.log(logger::debug_trace, "Failed to read ecdsa private key");
	}
	return {};
}

ssh_private_key load_raw_ssh_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	std::string_view type;
	if(r.read(type)) {
		if(type == "ssh-ed25519") {
			return load_raw_ed25519_private_key(r, crypto, call);
		} else if(type == "ssh-rsa") {
			return load_raw_rsa_private_key(r, crypto, call);
		} else if(type == "ecdsa-sha2-nistp256") {
			return load_raw_ecdsa_private_key(r, type, crypto, call);
		} else {
			call.log.log(logger::error, "Unknown private key type [{}]", type);
		}
	}
	return {};
}

// the magic string in beginning of openssh format (including the null char)
char const magic[] = "openssh-key-v1";
std::string_view const openssh_start = "-----BEGIN OPENSSH PRIVATE KEY-----";
std::string_view const openssh_end   = "-----END OPENSSH PRIVATE KEY-----";

bool is_openssh_private_key(std::string_view data) {
	return data.starts_with(openssh_start);
}

openssh_private_key::openssh_private_key(std::string_view view, crypto_context const& crypto, crypto_call_context const& call)
: crypto_(crypto)
, call_(call)
{
	if(is_openssh_private_key(view)) {
		// get the base64 encoded string
		std::string encoded_data;
		view = view.substr(openssh_start.size());
		for(std::string_view::size_type p = view.find_first_of("\n\r")
			; p != std::string_view::npos && !view.starts_with(openssh_end)
			; p = view.find_first_of("\n\r"))
		{
			if(p) {
				encoded_data += view.substr(0, p);
			}
			view = view.substr(p+1);
		}
		data_ = decode_base64(encoded_data);
		if(!data_.empty()) {
			if(!extract_info()) {
				data_.clear();
			}
		}
	}
}

openssh_private_key::openssh_private_key(ssh_private_key const& key, crypto_context const& crypto, crypto_call_context const& call)
: crypto_(crypto)
, call_(call)
{
	if(!construct_info(key)) {
		data_.clear();
	}
}

bool openssh_private_key::is_valid() const {
	return !data_.empty();
}

bool openssh_private_key::is_encrypted() const {
	return is_encrypted_;
}

bool openssh_private_key::extract_info() {
	ssh_bf_reader r(data_);

	std::optional<std::span<std::byte const, sizeof(magic)>> m;
	if(!r.read(m) || std::memcmp(m->data(), magic, sizeof(magic)) != 0) {
		call_.log.log(logger::error, "Failed to find openssh magic string");
		return false;
	}

	std::string_view cipher;
	if(!r.read(cipher)) {
		call_.log.log(logger::error, "Failed to read cipher");
		return false;
	}

	is_encrypted_ = cipher != "none";

	std::string_view kdf;
	if(!r.read(kdf) || (!is_encrypted_ && kdf != "none")) {
		call_.log.log(logger::error, "Failed to read or bad kdf");
		return false;
	}

	std::string_view kdf_options;
	if(!r.read(kdf_options) || (!is_encrypted_ && kdf_options != "")) {
		call_.log.log(logger::error, "Failed to read or bad kdf options");
		return false;
	}

	std::uint32_t pk_count = 0;
	if(!r.read(pk_count)) {
		call_.log.log(logger::error, "Failed to read public key count");
		return false;
	}

	// read out the public keys and ignore, we want only the private key
	for(std::uint32_t i = 0; i != pk_count; ++i) {
		std::string_view pk;
		if(!r.read(pk)) {
			call_.log.log(logger::error, "Failed to read public keys");
			return false;
		}
	}

	if(!r.read(priv_keys_)) {
		call_.log.log(logger::error, "Failed to read private key parts");
		return false;
	}

	return true;
}

bool openssh_private_key::construct_info(ssh_private_key const& key) {
	using namespace std::literals;
	ssh_bf_writer w(data_);

	if(!w.write(const_span{(std::byte const*)magic, sizeof(magic)}) ||
		!w.write("none"sv) || // cipher
		!w.write("none"sv) || // kdf
		!w.write(""sv) || // kdf options
		!w.write(std::uint32_t{1})) //num of keys
	{
		call_.log.log(logger::error, "Failed to write data");
		return false;
	}

	ssh_public_key pub = key.public_key();
	if(!w.write(to_string_view(to_byte_vector(pub)))) {
		call_.log.log(logger::error, "Failed to serialise public key");
		return false;
	}

	byte_vector priv;
	ssh_bf_writer priv_w(priv);
	std::uint32_t rand_int = call_.rand.random_uint(0, std::numeric_limits<std::uint32_t>::max());

	if(!priv_w.write(rand_int) ||
		!priv_w.write(rand_int) ||
		!priv_w.write(const_span(to_byte_vector(key))))
	{
		call_.log.log(logger::error, "Failed to serialise private key");
		return false;
	}

	// add padding to have block size of 8
	std::size_t bsize = priv_w.used_size() % 8;
	if(bsize) {
		bsize = 8-bsize;
	}
	std::uint8_t pad{1};
	while(bsize-- > 0) {
		if(!priv_w.write(pad++)) {
			call_.log.log(logger::error, "Failed to write padding");
			return false;
		}
	}

	std::size_t pos = w.used_size();

	if(!w.write(to_string_view(priv))) {
		call_.log.log(logger::error, "Failed to write data");
		return false;
	}

	priv_keys_ = to_string_view(safe_subspan(data_, pos, priv.size()));

	return true;
}

ssh_private_key openssh_private_key::construct() const {
	ssh_bf_reader priv_r(to_span(priv_keys_));

	// these are the check integers that can be used to check if the key was decrypted successfully
	std::uint32_t n1 = 0, n2 = 0;
	if(!priv_r.read(n1) || !priv_r.read(n2) || n1 != n2) {
		call_.log.log(logger::error, "Failed to read check integers or they don't match (encrypted private key?)");
		return {};
	}

	return load_raw_ssh_private_key(priv_r, crypto_, call_);
}

std::string openssh_private_key::serialise() const {
	std::string res;
	if(is_valid()) {
		res += openssh_start;
		res += "\n";
		std::string enc = encode_base64(data_, true);
		// split the base64 to 70 char lines
		while(!enc.empty()) {
			res += enc.substr(0, 70);
			res += "\n";
			enc = enc.substr(std::min<std::size_t>(enc.size(), 70));
		}
		res += openssh_end;
		res += "\n";
	}
	return res;
}

}
