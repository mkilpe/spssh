
#include "server.hpp"

#include "ssh/common/string_buffers.hpp"
#include "ssh/core/ssh_private_key.hpp"
#include "tools/common/command_parser.hpp"
#include "tools/common/util.hpp"

#include <coroutine>
#include <asio.hpp>
#include <asio/experimental/as_tuple.hpp>

#include <iostream>
#include <string>
#include <tuple>
#include <stdexcept>

namespace securepath::ssh {
namespace {

using tcp = asio::ip::tcp;
using namespace std::literals;

class ssh_session : public std::enable_shared_from_this<ssh_session>
{
public:
	ssh_session(tcp::socket socket, server_config const& config, logger& log, crypto_context& context)
	: socket_(std::move(socket))
	, timer_(socket_.get_executor())
	, log_(log)
	, server_(config, log, out_buf_, context)
	{
		timer_.expires_at(std::chrono::steady_clock::time_point::max());
	}

	void start() {
		log_.log(logger::info, "Connection accepted");

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->reader(); }, asio::detached);

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->writer(); }, asio::detached);

	}

private:
	void server_process() {
		transport_op res;
		std::size_t bsize;
		do {
			bsize = in_buf_.size();
			res = server_.process(in_buf_);
		} while(res != transport_op::disconnected && bsize != in_buf_.size());

		if(res == transport_op::disconnected) {
			stop();
		} else if(!out_buf_.empty()) {
			timer_.cancel_one();
		}
	}

	asio::awaitable<void> reader() {
		try {
			server_process();

			std::string read_data;
			read_data.resize(1024);
			for (; socket_.is_open();) {
				std::size_t n = co_await socket_.async_read_some(
					asio::buffer(read_data.data(), 1024), asio::use_awaitable);

				in_buf_.add(read_data.substr(0, n));
				server_process();
			}
		} catch (std::exception&) {
			stop();
		}
	}

	asio::awaitable<void> writer() {
		try {
			while (socket_.is_open()) {
				if (out_buf_.empty()) {
					asio::error_code ec;
					co_await timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
				} else {
					std::string buf = out_buf_.extract_committed();
					log_.log(logger::debug, "writing out: {}", to_span(buf));
					co_await asio::async_write(socket_, asio::buffer(buf), asio::use_awaitable);
				}
			}
		} catch (std::exception&) {
			stop();
		}
	}

	void stop() {
		log_.log(logger::info, "Closing connection");
		socket_.close();
		timer_.cancel();
	}

	tcp::socket socket_;
	asio::steady_timer timer_;

	string_in_buffer in_buf_;
	string_out_buffer out_buf_;

	logger& log_;
	ssh_test_server server_;
};

asio::awaitable<void> listen(tcp::acceptor& acceptor, server_config const& config, logger& log, crypto_context& crypto)
{
	log.log(logger::info, "Ready to accept connections");

	for (;;) {
		auto [e, conn] = co_await acceptor.async_accept(asio::experimental::as_tuple(asio::use_awaitable));
		if(!e) {
			std::make_shared<ssh_session>(std::move(conn), config, log, crypto)->start();
		} else {
			std::cerr << "Accept failed: " << e.message() << "\n";
			asio::steady_timer timer(co_await asio::this_coro::executor);
			timer.expires_after(100ms);
			co_await timer.async_wait(asio::use_awaitable);
		}
	}
}


struct test_server_commands : server_config, securepath::command_parser {
	bool help{};
	std::string bind_address;
	std::uint16_t port{22};
	std::string key_file;

	test_server_commands() {
		add(help, "help", "", "show help");
		add(bind_address, "bind", "b", "bind address");
		add(port, "port", "p", "port to listen");
		add(key_file, "key", "", "ssh host private key");
	}

	void create_config(crypto_context const& crypto, crypto_call_context const& call) {

		side = transport_side::server;
		my_version.software = "spssh_test_server";

		algorithms.host_keys = {key_type::ssh_ed25519};
		algorithms.kexes = {kex_type::curve25519_sha256};
		algorithms.client_server_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm};
		algorithms.server_client_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm};
		algorithms.client_server_macs = {mac_type::aes_256_gcm};
		algorithms.server_client_macs = {mac_type::aes_256_gcm};

		random_packet_padding = false;

		//if(key_file.empty()) {
		//	throw std::runtime_error("Host key required");
		//}

		auto key = load_raw_base64_ssh_private_key(
			"AAAAC3NzaC1lZDI1NTE5AAAAIKybvEDG+Tp2x91UjeDAFwmeOfitihW8fKN4rzMf2DBnAAAAQEee9Mvoputz204F1EtY51yPsLFm10kpJOw1tMVVyZT2rJu8QMb5OnbH3VSN4MAXCZ45+K2KFbx8o3ivMx/YMGcAAAARbWlrYWVsQG1pa2FlbC1kZXYBAgME",
			crypto, call);

		add_private_key(std::move(key));
		/*
		auto pkey = load_ssh_private_key(read_file(key_file), crypto, call);
		if(!pkey.valid()) {
			throw std::runtime_error("could not load private key");
		}
		add_private_key(std::move(pkey));
		*/

	}

};

}
}

int main(int argc, char* argv[]) {
	try {
		using namespace securepath::ssh;
		test_server_commands p;
		p.parse(argc, argv);
		if(p.help) {
			std::cout << "spssh test server\n";
			test_server_commands().print_help(std::cout);
			return 0;
		}

		stdout_logger log;

		auto crypto = default_crypto_context();
		auto rand = crypto.construct_random();
		crypto_call_context call(log, *rand);

		p.create_config(crypto, call);

		asio::io_context io_context;

		asio::signal_set signals(io_context, SIGINT, SIGTERM);
		signals.async_wait([&](auto, auto){ io_context.stop(); });

		auto result = tcp::resolver(io_context).resolve(p.bind_address, "ssh", tcp::resolver::passive);
		if(result.begin() == result.end()) {
			std::cerr << "Failed to resolve address\n";
			return 1;
		}

		auto endpoint = result.begin()->endpoint();
		endpoint.port(p.port);

		tcp::acceptor acceptor(io_context, endpoint);
		asio::co_spawn(io_context, securepath::ssh::listen(acceptor, p, log, crypto), asio::detached);

		io_context.run();
	} catch(std::exception const& e) {
		std::cerr << "Exception: " << e.what() << "\n";
		return 1;
	}
}
