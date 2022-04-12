
#include "ssh/common/string_buffers.hpp"
#include "ssh/client/ssh_client.hpp"

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

static ssh_config client_config() {
	ssh_config c;
	c.side = transport_side::client;
	c.my_version.software = "spssh-test-client";
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	c.random_packet_padding = false;

	return c;
}


class ssh_session : public std::enable_shared_from_this<ssh_session>
{
public:
	ssh_session(tcp::socket socket, ssh_config const& config, logger& log)
	: socket_(std::move(socket))
	, timer_(socket_.get_executor())
	, log_(log)
	, client_(config, log, out_buf_)
	{
		timer_.expires_at(std::chrono::steady_clock::time_point::max());
	}

	void start() {
		log_.log(logger::info, "Connected");

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->reader(); }, asio::detached);

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->writer(); }, asio::detached);

	}

private:
	void client_process() {
		transport_op res;
		std::size_t bsize;
		do {
			bsize = in_buf_.size();
			res = client_.process(in_buf_);
		} while(res != transport_op::disconnected && bsize != in_buf_.size());

		if(res == transport_op::disconnected) {
			stop();
		} else if(!out_buf_.empty()) {
			timer_.cancel_one();
		}
	}

	asio::awaitable<void> reader() {
		try {
			client_process();

			std::string read_data;
			read_data.resize(1024);
			for (; socket_.is_open();) {
				std::size_t n = co_await socket_.async_read_some(
					asio::buffer(read_data.data(), 1024), asio::use_awaitable);

				in_buf_.add(read_data.substr(0, n));
				client_process();
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
	ssh_client client_;
};

struct client_context {
	stdout_logger log;
	ssh_config config = client_config();
};

asio::awaitable<void> connect(asio::io_context& io_context, client_context& client_c, tcp::endpoint ep)
{
	client_c.log.log(logger::info, "Connecting to {}", ep);

	tcp::socket s(io_context);
	auto [e] = co_await s.async_connect(ep, asio::experimental::as_tuple(asio::use_awaitable));
	if(!e) {
		std::make_shared<ssh_session>(std::move(s), client_c.config, client_c.log)->start();
	} else {
		std::cerr << "Connect failed: " << e.message() << "\n";
	}
}

}
}

int main(int argc, char* argv[]) {
	try {
		if(argc != 3) {
			std::cout << argv[0] << " <host> <port>\n";
			return 0;
		}

		using namespace securepath::ssh;

		asio::io_context io_context;

		asio::signal_set signals(io_context, SIGINT, SIGTERM);
		signals.async_wait([&](auto, auto){ io_context.stop(); });

		auto result = tcp::resolver(io_context).resolve(argv[1], "ssh");
		if(result.begin() == result.end()) {
			std::cerr << "Failed to resolve address\n";
			return 1;
		}

		auto endpoint = result.begin()->endpoint();
		endpoint.port(atoi(argv[2]));

		client_context c_context;

		asio::co_spawn(io_context, securepath::ssh::connect(io_context, c_context, endpoint), asio::detached);

		io_context.run();
	} catch(std::exception const& e) {
		std::cerr << "Exception: " << e.what() << "\n";
		return 1;
	}
}
