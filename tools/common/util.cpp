#include "util.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <syncstream>

#if defined(_WIN32)
#	define WIN32_LEAN_AND_MEAN
#	define NOMINMAX
#	include <windows.h>
#else
#	include <termios.h>
#	include <unistd.h>
#endif

namespace securepath::ssh {

byte_vector read_file(std::string const& file) {
	byte_vector b;
	std::ifstream f(file, std::ios_base::binary);
	if(f) {
		f.seekg(0, std::ios_base::end);
		auto size = f.tellg();
		f.seekg(0, std::ios_base::beg);
		b.resize(size);
		f.read((char*)b.data(), size);
	}
	return b;
}

namespace {

// turns terminal echo off for its lifetime when asked and possible, restoring it on destruction
class scoped_echo_off {
public:
	explicit scoped_echo_off(bool disable) {
		if(disable) {
			enable_off();
		}
	}
	~scoped_echo_off() {
		if(active_) {
			restore();
		}
	}
	scoped_echo_off(scoped_echo_off const&) = delete;
	scoped_echo_off& operator=(scoped_echo_off const&) = delete;

	bool active() const { return active_; }

private:
#if defined(_WIN32)
	void enable_off() {
		handle_ = ::GetStdHandle(STD_INPUT_HANDLE);
		if(handle_ != INVALID_HANDLE_VALUE && ::GetConsoleMode(handle_, &saved_)) {
			active_ = ::SetConsoleMode(handle_, saved_ & ~ENABLE_ECHO_INPUT) != 0;
		}
	}
	void restore() { ::SetConsoleMode(handle_, saved_); }

	HANDLE handle_{};
	DWORD saved_{};
#else
	void enable_off() {
		if(::isatty(STDIN_FILENO) == 1 && ::tcgetattr(STDIN_FILENO, &saved_) == 0) {
			termios raw = saved_;
			raw.c_lflag &= ~tcflag_t(ECHO);
			active_ = ::tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0;
		}
	}
	void restore() { ::tcsetattr(STDIN_FILENO, TCSANOW, &saved_); }

	termios saved_{};
#endif
	bool active_{};
};

}

std::string prompt_input(std::string const& prompt, bool echo) {
	std::cout << prompt << std::flush;

	scoped_echo_off guard(!echo);

	std::string line;
	std::getline(std::cin, line);

	if(guard.active()) {
		// the newline the user typed was not echoed, so add one to move to the next line
		std::cout << std::endl;
	}
	return line;
}

ssh_config test_tool_default_config() {
	ssh_config c;

	c.algorithms.host_keys = {key_type::ssh_ed25519, key_type::ssh_rsa, key_type::ecdsa_sha2_nistp256};
	c.algorithms.kexes = {kex_type::curve25519_sha256, kex_type::libssh_curve25519_sha256, kex_type::dh_group16_sha512, kex_type::dh_group14_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm, cipher_type::aes_256_ctr};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm, cipher_type::aes_256_ctr};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm, mac_type::hmac_sha2_256};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm, mac_type::hmac_sha2_256};

	c.random_packet_padding = false;

	return c;
}

std::string tokenise_command(std::string const& line, std::vector<std::string>& args) {
	std::string cmd;
	std::string str;
	std::istringstream in(line);
	while(in >> std::quoted(str)) {
		if(cmd.empty()) {
			cmd = str;
		} else {
			args.push_back(str);
		}
	}
	return cmd;
}

void sync_cout_logger::do_log_line(type, std::string const& line, std::source_location&&) {
	std::osyncstream out(std::cout);
	out << line << std::endl;
}

}