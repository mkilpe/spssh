
#include "client.hpp"
#include "ssh/common/string_buffers.hpp"
#include "tools/common/config_parser.hpp"
#include "tools/common/util.hpp"

#include <coroutine>
#include <asio.hpp>
#include <asio/experimental/as_tuple.hpp>

#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <stdexcept>

namespace securepath::ssh {
namespace {

using tcp = asio::ip::tcp;
using namespace std::literals;

class ssh_client_session : public std::enable_shared_from_this<ssh_client_session>
{
public:
	ssh_client_session(asio::io_context& io_context, logger& log, crypto_context ccontext, client_config const& config)
	: io_context_(io_context)
	, socket_(io_context_)
	, timer_(io_context_)
	, log_(log)
	, client_(config, log_, out_buf_, ccontext)
	{
		timer_.expires_at(std::chrono::steady_clock::time_point::max());
	}

	asio::awaitable<void> connect(tcp::endpoint ep) {
		log_.log(logger::info, "Connecting to {}", ep);

		auto [e] = co_await socket_.async_connect(ep, asio::experimental::as_tuple(asio::use_awaitable));
		if(!e) {
			start();
		} else {
			std::cerr << "Connect failed: " << e.message() << "\n";
			io_context_.stop();
		}
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

		io_context_.stop();
	}

private:
	asio::io_context& io_context_;
	tcp::socket socket_;
	asio::steady_timer timer_;

	logger& log_;

	string_in_buffer in_buf_;
	string_out_buffer out_buf_;

	ssh_test_client client_;
};


struct test_client_commands : client_config, securepath::command_parser {
	bool help{};
	std::string host;
	std::uint16_t port{22};
	std::string config_file;

	config_parser config;

	test_client_commands()
	: client_config(test_tool_default_config())
	{
		add(help, "help", "", "show help");
		add(host, "host", "h", "host to connect");
		add(port, "port", "p", "port to connect");
		add(username, "user", "u", "username to connect");
		add(password, "password", "", "password");
		add(config_file, "config", "c", "config file");

		config.add_commands(*this);
	}

	void create_config(logger& log) {

		side = transport_side::client;
		my_version.software = "spssh_test_client";

		config.parse(log, *this);
	}

};
}
}

int main(int argc, char* argv[]) {
	try {
		using namespace securepath::ssh;
		test_client_commands p;
		p.parse(argc, argv);
		if(p.help) {
			std::cout << "spssh test client\n";
			test_client_commands().print_help(std::cout);
			return 0;
		}
		if(!p.config_file.empty()) {
			p.parse_file(p.config_file);
		}

		stdout_logger log;

		p.create_config(log);

		asio::io_context io_context;

		asio::signal_set signals(io_context, SIGINT, SIGTERM);
		signals.async_wait([&](auto, auto){ io_context.stop(); });

		auto result = tcp::resolver(io_context).resolve(p.host, "ssh");
		if(result.begin() == result.end()) {
			std::cerr << "Failed to resolve address\n";
			return 1;
		}

		auto endpoint = result.begin()->endpoint();
		endpoint.port(p.port);

		auto client = std::make_shared<ssh_client_session>(io_context, log, p.config.get_crypto_context(), p);
		asio::co_spawn(io_context, client->connect(endpoint), asio::detached);

		io_context.run();
	} catch(std::exception const& e) {
		std::cerr << "Exception: " << e.what() << "\n";
		return 1;
	}
}
