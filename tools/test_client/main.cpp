
#include "client.hpp"
#include "ssh/common/string_buffers.hpp"

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

class ssh_client_session : public std::enable_shared_from_this<ssh_client_session>
{
public:
	ssh_client_session(asio::io_context& io_context)
	: io_context_(io_context)
	, socket_(io_context_)
	, timer_(io_context_)
	, client_(config_, log_, out_buf_)
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

	asio::io_context& io_context_;
	tcp::socket socket_;
	asio::steady_timer timer_;

	stdout_logger log_;
	ssh_config config_ = test_client_config();

	string_in_buffer in_buf_;
	string_out_buffer out_buf_;

	ssh_test_client client_;
};

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

		auto client = std::make_shared<ssh_client_session>(io_context);
		asio::co_spawn(io_context, client->connect(endpoint), asio::detached);

		io_context.run();
	} catch(std::exception const& e) {
		std::cerr << "Exception: " << e.what() << "\n";
		return 1;
	}
}
