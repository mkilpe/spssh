#include "sftp_transfer.hpp"
#include "packet_types.hpp"
#include "ssh/common/util.hpp"

#include <algorithm>

namespace securepath::ssh::sftp {

// ---- inputs and outputs ------------------------------------------------------------------------------------------

file_output::file_output(std::filesystem::path const& path)
: file_(path, std::ios::binary | std::ios::out | std::ios::trunc)
{
}

bool file_output::write(std::uint64_t offset, const_span data) {
	file_.seekp(std::streamoff(offset));
	file_.write(reinterpret_cast<char const*>(data.data()), std::streamsize(data.size()));
	return file_.good();
}

bool file_output::finish() {
	file_.flush();
	bool res = file_.good();
	file_.close();
	return res && !file_.fail();
}

file_input::file_input(std::filesystem::path const& path)
: file_(path, std::ios::binary | std::ios::in)
{
	std::error_code ec;
	auto s = std::filesystem::file_size(path, ec);
	if(!ec) {
		size_ = s;
	}
}

std::size_t file_input::read(std::uint64_t offset, span out) {
	file_.clear();
	file_.seekg(std::streamoff(offset));
	file_.read(reinterpret_cast<char*>(out.data()), std::streamsize(out.size()));
	return file_.bad() ? 0 : std::size_t(file_.gcount());
}

bool memory_output::write(std::uint64_t offset, const_span data) {
	if(!data.empty()) {
		if(offset + data.size() > target_.size()) {
			target_.resize(offset + data.size());
		}
		std::copy(data.begin(), data.end(), target_.begin() + std::ptrdiff_t(offset));
	}
	return true;
}

std::size_t memory_input::read(std::uint64_t offset, span out) {
	std::size_t n = 0;
	if(offset < data_.size()) {
		n = std::min(out.size(), std::size_t(data_.size() - offset));
		std::copy(data_.begin() + std::ptrdiff_t(offset), data_.begin() + std::ptrdiff_t(offset + n), out.begin());
	}
	return n;
}

// ---- one transfer -------------------------------------------------------------------------------------------------

namespace {

template<typename... F> struct overloaded : F... { using F::operator()...; };
template<typename... F> overloaded(F...) -> overloaded<F...>;

struct chunk {
	std::uint64_t offset{};
	std::uint32_t size{};
};

}

struct sftp_transfer_handler::transfer {
	enum class direction { download, upload };

	transfer(sftp_transfer_handler& handler, transfer_id id, direction dir, sftp_client_interface& client, std::string path
		, transfer_options options, transfer_done done, transfer_progress progress)
	: handler_(handler)
	, id_(id)
	, direction_(dir)
	, client_(client)
	, path_(std::move(path))
	, options_(options)
	, done_(std::move(done))
	, progress_(std::move(progress))
	{
		options_.chunk_size = std::max<std::uint32_t>(options_.chunk_size, 1);
		options_.max_in_flight = std::max<std::size_t>(options_.max_in_flight, 1);
	}

	void set_output(std::unique_ptr<transfer_output> o) { output_ = std::move(o); }
	void set_input(std::unique_ptr<transfer_input> i) { input_ = std::move(i); }

	transfer_id id() const { return id_; }
	bool finished() const { return finished_; }

	/// send the open request, false if it could not be sent
	bool start() {
		call_handle h{};
		if(direction_ == direction::download) {
			h = client_.open_file(path_, fxf_read);
		} else {
			file_attributes attrs;
			attrs.permissions = options_.permissions;
			auto mode = open_mode(fxf_write | fxf_creat | (options_.exclusive ? fxf_excl : fxf_trunc));
			h = client_.open_file(path_, mode, attrs);
		}
		if(h) {
			handler_.track(h, id_);
		}
		return h != 0;
	}

	void on_result(call_handle h, call_result const& r) {
		if(!finished_) {
			std::visit(overloaded{
				[&](sftp_error const& e) { fail(e); },
				[&](open_file_data const& d) { on_opened(d.handle); },
				[&](stat_file_data const& d) { on_attrs(d.attrs); },
				[&](read_file_data const& d) { on_read(h, d.data); },
				[&](write_file_data const&) { on_written(h); },
				[&](close_file_data const&) { on_closed(); },
				[&](auto const&) { fail(sftp_error{fx_failure, "unexpected result"}); }
			}, r);
		}
	}

	void on_send_more() {
		if(!finished_ && paused_) {
			paused_ = false;
			continue_transfer();
		}
	}

	void cancel() {
		if(!finished_) {
			result_.cancelled = true;
			fail(sftp_error{});
		}
	}

	void invoke_done() {
		if(done_) {
			done_(id_, result_);
		}
	}

private:
	/// records the request; a handle of 0 means the channel could not take it, so wait for on_send_more
	bool track(call_handle h) {
		if(h) {
			handler_.track(h, id_);
		} else {
			paused_ = true;
			++result_.pauses;
		}
		return h != 0;
	}

	void continue_transfer() {
		if(direction_ == direction::download) {
			issue_reads();
		} else {
			issue_writes();
		}
	}

	void on_opened(file_handle const& h) {
		handle_ = h;
		open_ = true;
		if(direction_ == direction::download && options_.stat_first) {
			track(client_.stat_file(handle_));
		} else {
			continue_transfer();
		}
	}

	void on_attrs(file_attributes const& attrs) {
		result_.attrs = attrs;
		if(attrs.size) {
			end_ = *attrs.size;
		}
		issue_reads();
	}

	bool more_to_read() const {
		return !eof_ && (!end_ || next_offset_ < *end_);
	}

	void issue_reads() {
		// the tails of short reads go first, then new ground
		while(!paused_ && in_flight_.size() < options_.max_in_flight && (!pending_.empty() || more_to_read())) {
			bool from_pending = !pending_.empty();
			chunk c = from_pending ? pending_.front() : chunk{next_offset_, options_.chunk_size};
			if(track(client_.read_file(handle_, c.offset, c.size))) {
				in_flight_[last_tracked_] = c;
				if(from_pending) {
					pending_.pop_front();
				} else {
					next_offset_ += c.size;
				}
			}
		}
		maybe_close();
	}

	void on_read(call_handle h, const_span data) {
		auto it = in_flight_.find(h);
		if(it == in_flight_.end()) {
			fail(sftp_error{fx_failure, "unexpected read result"});
		} else {
			chunk c = it->second;
			in_flight_.erase(it);
			if(data.empty()) {
				// the file ends at or before this offset, tails past it are moot
				eof_ = true;
				end_ = end_ ? std::min(*end_, c.offset) : c.offset;
				std::erase_if(pending_, [&](chunk const& p) { return p.offset >= *end_; });
			} else if(!output_->write(c.offset, data)) {
				fail(sftp_error{fx_failure, "writing the output failed"});
			} else {
				result_.bytes += data.size();
				report_progress();
				bool short_read = data.size() < c.size && (!end_ || c.offset + data.size() < *end_);
				if(short_read) {
					pending_.push_back(chunk{c.offset + data.size(), std::uint32_t(c.size - data.size())});
				}
			}
			if(!finished_) {
				issue_reads();
			}
		}
	}

	void issue_writes() {
		while(!paused_ && in_flight_.size() < options_.max_in_flight && !input_eof_) {
			if(!parked_) {
				buffer_.resize(options_.chunk_size);
				std::size_t n = input_->read(next_offset_, buffer_);
				if(n == 0) {
					input_eof_ = true;
				} else {
					parked_ = chunk{next_offset_, std::uint32_t(n)};
					next_offset_ += n;
				}
			}
			if(parked_ && track(client_.write_file(handle_, parked_->offset, const_span(buffer_.data(), parked_->size)))) {
				in_flight_[last_tracked_] = *parked_;
				parked_.reset();
			}
		}
		maybe_close();
	}

	void on_written(call_handle h) {
		auto it = in_flight_.find(h);
		if(it == in_flight_.end()) {
			fail(sftp_error{fx_failure, "unexpected write result"});
		} else {
			result_.bytes += it->second.size;
			in_flight_.erase(it);
			report_progress();
			if(!finished_) {
				issue_writes();
			}
		}
	}

	bool all_sent() const {
		if(direction_ == direction::download) {
			return !more_to_read() && pending_.empty();
		}
		return input_eof_ && !parked_;
	}

	void maybe_close() {
		if(!closing_ && open_ && in_flight_.empty() && all_sent()) {
			closing_ = track(client_.close_file(handle_));
		}
	}

	void on_closed() {
		open_ = false;
		if(direction_ == direction::download && !output_->finish()) {
			fail(sftp_error{fx_failure, "finishing the output failed"});
		} else {
			finished_ = true;
		}
	}

	void fail(sftp_error err) {
		if(!finished_) {
			result_.error = std::move(err);
			finished_ = true;
			// best effort close of the remote handle, its result is dropped as this transfer is gone by then
			if(open_ && !closing_) {
				auto h = client_.close_file(handle_);
				if(h) {
					handler_.track(h, id_);
				}
			}
		}
	}

	void report_progress() {
		if(progress_) {
			progress_(id_, result_.bytes);
		}
	}

	friend class sftp_transfer_handler;

private:
	sftp_transfer_handler& handler_;
	transfer_id id_;
	direction direction_;
	sftp_client_interface& client_;
	std::string path_;
	transfer_options options_;
	transfer_done done_;
	transfer_progress progress_;
	std::unique_ptr<transfer_output> output_;
	std::unique_ptr<transfer_input> input_;

	file_handle handle_;
	bool open_{};
	bool closing_{};
	bool finished_{};
	bool paused_{};
	bool eof_{};
	bool input_eof_{};
	std::uint64_t next_offset_{};
	std::optional<std::uint64_t> end_;
	std::map<call_handle, chunk> in_flight_;
	std::deque<chunk> pending_;
	std::optional<chunk> parked_;
	byte_vector buffer_;
	call_handle last_tracked_{};
	transfer_result result_;
};

// ---- the handler --------------------------------------------------------------------------------------------------

sftp_transfer_handler::sftp_transfer_handler(std::shared_ptr<sftp_client_callback> next)
: next_(std::move(next))
{
}

sftp_transfer_handler::~sftp_transfer_handler() = default;

bool sftp_transfer_handler::call(call_handle h, call_completion completion) {
	if(h) {
		calls_[h] = std::move(completion);
	}
	return h != 0;
}

void sftp_transfer_handler::track(call_handle h, transfer_id id) {
	owners_[h] = id;
	if(auto it = transfers_.find(id); it != transfers_.end()) {
		it->second->last_tracked_ = h;
	}
}

transfer_id sftp_transfer_handler::start(std::unique_ptr<transfer> t) {
	transfer_id id = t->id();
	// the transfer has to be findable while it sends its first request
	auto& slot = transfers_[id];
	slot = std::move(t);
	if(!slot->start()) {
		transfers_.erase(id);
		id = 0;
	}
	return id;
}

transfer_id sftp_transfer_handler::download(sftp_client_interface& client, std::string remote_path
	, std::unique_ptr<transfer_output> output, transfer_options options, transfer_done done, transfer_progress progress)
{
	auto t = std::make_unique<transfer>(*this, ++next_id_, transfer::direction::download, client, std::move(remote_path)
		, options, std::move(done), std::move(progress));
	t->set_output(std::move(output));
	return start(std::move(t));
}

transfer_id sftp_transfer_handler::upload(sftp_client_interface& client, std::string remote_path
	, std::unique_ptr<transfer_input> input, transfer_options options, transfer_done done, transfer_progress progress)
{
	auto t = std::make_unique<transfer>(*this, ++next_id_, transfer::direction::upload, client, std::move(remote_path)
		, options, std::move(done), std::move(progress));
	t->set_input(std::move(input));
	return start(std::move(t));
}

bool sftp_transfer_handler::cancel(transfer_id id) {
	auto it = transfers_.find(id);
	bool res = it != transfers_.end();
	if(res) {
		it->second->cancel();
		finish_if_done(id);
	}
	return res;
}

void sftp_transfer_handler::finish_if_done(transfer_id id) {
	auto it = transfers_.find(id);
	if(it != transfers_.end() && it->second->finished()) {
		// keep the transfer alive while its done callback runs, it may start new transfers
		auto t = std::move(it->second);
		transfers_.erase(it);
		t->invoke_done();
	}
}

bool sftp_transfer_handler::deliver(call_handle h, call_result const& r) {
	bool res = false;
	if(auto owner = owners_.find(h); owner != owners_.end()) {
		transfer_id id = owner->second;
		owners_.erase(owner);
		res = true;
		// results for transfers that are already gone (the close sent when aborting) are dropped
		if(auto t = transfers_.find(id); t != transfers_.end()) {
			t->second->on_result(h, r);
			finish_if_done(id);
		}
	} else if(auto c = calls_.find(h); c != calls_.end()) {
		auto completion = std::move(c->second);
		calls_.erase(c);
		res = true;
		completion(r);
	}
	return res;
}

template<typename T>
void sftp_transfer_handler::route(call_handle h, T result, void (sftp_client_callback::*forward)(call_handle, T)) {
	if(!deliver(h, call_result{result}) && next_) {
		((*next_).*forward)(h, std::move(result));
	}
}

bool sftp_transfer_handler::on_version(std::uint32_t version, std::vector<ext_data_view> const& extensions) {
	return next_ ? next_->on_version(version, extensions) : true;
}

void sftp_transfer_handler::on_failure(call_handle h, sftp_error err) {
	if(!deliver(h, call_result{err}) && next_) {
		next_->on_failure(h, std::move(err));
	}
}

void sftp_transfer_handler::on_open_file(call_handle h, open_file_data r) { route(h, std::move(r), &sftp_client_callback::on_open_file); }
void sftp_transfer_handler::on_read_file(call_handle h, read_file_data r) { route(h, std::move(r), &sftp_client_callback::on_read_file); }
void sftp_transfer_handler::on_write_file(call_handle h, write_file_data r) { route(h, std::move(r), &sftp_client_callback::on_write_file); }
void sftp_transfer_handler::on_close_file(call_handle h, close_file_data r) { route(h, std::move(r), &sftp_client_callback::on_close_file); }
void sftp_transfer_handler::on_stat_file(call_handle h, stat_file_data r) { route(h, std::move(r), &sftp_client_callback::on_stat_file); }
void sftp_transfer_handler::on_setstat_file(call_handle h, setstat_file_data r) { route(h, std::move(r), &sftp_client_callback::on_setstat_file); }
void sftp_transfer_handler::on_open_dir(call_handle h, open_dir_data r) { route(h, std::move(r), &sftp_client_callback::on_open_dir); }
void sftp_transfer_handler::on_read_dir(call_handle h, read_dir_data r) { route(h, std::move(r), &sftp_client_callback::on_read_dir); }
void sftp_transfer_handler::on_close_dir(call_handle h, close_dir_data r) { route(h, std::move(r), &sftp_client_callback::on_close_dir); }
void sftp_transfer_handler::on_remove_file(call_handle h, remove_file_data r) { route(h, std::move(r), &sftp_client_callback::on_remove_file); }
void sftp_transfer_handler::on_rename(call_handle h, rename_data r) { route(h, std::move(r), &sftp_client_callback::on_rename); }
void sftp_transfer_handler::on_mkdir(call_handle h, mkdir_data r) { route(h, std::move(r), &sftp_client_callback::on_mkdir); }
void sftp_transfer_handler::on_remove_dir(call_handle h, remove_dir_data r) { route(h, std::move(r), &sftp_client_callback::on_remove_dir); }
void sftp_transfer_handler::on_stat(call_handle h, stat_data r) { route(h, std::move(r), &sftp_client_callback::on_stat); }
void sftp_transfer_handler::on_setstat(call_handle h, setstat_data r) { route(h, std::move(r), &sftp_client_callback::on_setstat); }
void sftp_transfer_handler::on_readlink(call_handle h, readlink_data r) { route(h, std::move(r), &sftp_client_callback::on_readlink); }
void sftp_transfer_handler::on_symlink(call_handle h, symlink_data r) { route(h, std::move(r), &sftp_client_callback::on_symlink); }
void sftp_transfer_handler::on_realpath(call_handle h, realpath_data r) { route(h, std::move(r), &sftp_client_callback::on_realpath); }
void sftp_transfer_handler::on_extended(call_handle h, extended_data r) { route(h, std::move(r), &sftp_client_callback::on_extended); }

void sftp_transfer_handler::on_send_more() {
	// a transfer may finish or start others from its callbacks, so walk a snapshot of the ids
	std::vector<transfer_id> ids;
	for(auto const& [id, t] : transfers_) {
		ids.push_back(id);
	}
	for(auto id : ids) {
		if(auto it = transfers_.find(id); it != transfers_.end()) {
			it->second->on_send_more();
			finish_if_done(id);
		}
	}
	if(next_) {
		next_->on_send_more();
	}
}

}
