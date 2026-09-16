#ifndef SP_SSH_SFTP_TRANSFER_HEADER
#define SP_SSH_SFTP_TRANSFER_HEADER

#include "sftp_client_interface.hpp"
#include "ssh/common/types.hpp"

#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace securepath::ssh::sftp {

/// Destination of a download. Offsets are explicit as the replies to pipelined reads can arrive in any order.
class transfer_output {
public:
	virtual ~transfer_output() = default;
	/// write data at offset, false on error
	virtual bool write(std::uint64_t offset, const_span data) = 0;
	/// everything has been written, flush and close; false on error
	virtual bool finish() = 0;
};

/// Source of an upload.
class transfer_input {
public:
	virtual ~transfer_input() = default;
	/// total size if known
	virtual std::optional<std::uint64_t> size() const = 0;
	/// read into out from offset, returns the amount read, 0 at the end
	virtual std::size_t read(std::uint64_t offset, span out) = 0;
};

class file_output : public transfer_output {
public:
	explicit file_output(std::filesystem::path const& path);

	bool is_open() const { return file_.is_open(); }
	bool write(std::uint64_t offset, const_span data) override;
	bool finish() override;

private:
	std::ofstream file_;
};

class file_input : public transfer_input {
public:
	explicit file_input(std::filesystem::path const& path);

	bool is_open() const { return file_.is_open(); }
	std::optional<std::uint64_t> size() const override { return size_; }
	std::size_t read(std::uint64_t offset, span out) override;

private:
	std::ifstream file_;
	std::optional<std::uint64_t> size_;
};

class memory_output : public transfer_output {
public:
	explicit memory_output(byte_vector& target) : target_(target) {}

	bool write(std::uint64_t offset, const_span data) override;
	bool finish() override { return true; }

private:
	byte_vector& target_;
};

class memory_input : public transfer_input {
public:
	explicit memory_input(const_span data) : data_(data) {}

	std::optional<std::uint64_t> size() const override { return data_.size(); }
	std::size_t read(std::uint64_t offset, span out) override;

private:
	const_span data_;
};

using transfer_id = std::uint32_t;

struct transfer_options {
	/// size of a single read or write request
	std::uint32_t chunk_size{32*1024};
	/// requests kept outstanding at a time
	std::size_t max_in_flight{16};
	/// upload: refuse to overwrite an existing file (otherwise it is created or truncated)
	bool exclusive{};
	/// upload: permissions for the created file
	std::optional<std::uint32_t> permissions;
	/// download: fetch the attributes first so that the size is known
	bool stat_first{true};
};

struct transfer_result {
	std::uint64_t bytes{};
	/// download: the remote attributes when they were fetched
	std::optional<file_attributes> attrs;
	/// set when the transfer failed
	sftp_error error;
	bool cancelled{};
	/// how many times sending had to wait for the channel
	std::uint32_t pauses{};
};

using transfer_done = std::function<void(transfer_id, transfer_result const&)>;
using transfer_progress = std::function<void(transfer_id, std::uint64_t bytes)>;

/// result of one request routed by sftp_transfer_handler::call: the result of the operation, or the error;
/// the views inside are valid during the completion only
using call_result = std::variant<sftp_error, open_file_data, read_file_data, write_file_data, close_file_data
	, stat_file_data, setstat_file_data, open_dir_data, read_dir_data, close_dir_data, remove_file_data, rename_data
	, mkdir_data, remove_dir_data, stat_data, setstat_data, readlink_data, symlink_data, realpath_data, extended_data>;
using call_completion = std::function<void(call_result const&)>;

/** \brief sftp_client_callback that runs file transfers and routes single requests to completions
 *
 *  Give this to the sftp_client as its callback. Results of the requests it owns are consumed here, everything
 *  else is forwarded to the next callback, which may be left empty.
 */
class sftp_transfer_handler : public sftp_client_callback {
public:
	explicit sftp_transfer_handler(std::shared_ptr<sftp_client_callback> next = {});
	~sftp_transfer_handler();

	/// deliver the result of the request to completion instead of the next callback; false if handle is 0
	bool call(call_handle, call_completion);

	/// start a transfer; returns 0 if the first request could not be sent, in which case nothing is called back
	transfer_id download(sftp_client_interface&, std::string remote_path, std::unique_ptr<transfer_output>
		, transfer_options, transfer_done, transfer_progress = {});
	transfer_id upload(sftp_client_interface&, std::string remote_path, std::unique_ptr<transfer_input>
		, transfer_options, transfer_done, transfer_progress = {});

	/// abort a transfer, done is called with cancelled set; false if there is no such transfer
	bool cancel(transfer_id);
	std::size_t active_transfers() const { return transfers_.size(); }

	bool on_version(std::uint32_t version, std::vector<ext_data_view> const& extensions) override;
	void on_failure(call_handle, sftp_error) override;
	void on_open_file(call_handle, open_file_data result) override;
	void on_read_file(call_handle, read_file_data result) override;
	void on_write_file(call_handle, write_file_data result) override;
	void on_close_file(call_handle, close_file_data result) override;
	void on_stat_file(call_handle, stat_file_data result) override;
	void on_setstat_file(call_handle, setstat_file_data result) override;
	void on_open_dir(call_handle, open_dir_data result) override;
	void on_read_dir(call_handle, read_dir_data result) override;
	void on_close_dir(call_handle, close_dir_data result) override;
	void on_remove_file(call_handle, remove_file_data result) override;
	void on_rename(call_handle, rename_data result) override;
	void on_mkdir(call_handle, mkdir_data result) override;
	void on_remove_dir(call_handle, remove_dir_data result) override;
	void on_stat(call_handle, stat_data result) override;
	void on_setstat(call_handle, setstat_data result) override;
	void on_readlink(call_handle, readlink_data result) override;
	void on_symlink(call_handle, symlink_data result) override;
	void on_realpath(call_handle, realpath_data result) override;
	void on_extended(call_handle, extended_data result) override;
	void on_send_more() override;

private:
	struct transfer;
	friend struct transfer;

	template<typename T>
	void route(call_handle, T result, void (sftp_client_callback::*forward)(call_handle, T));
	bool deliver(call_handle, call_result const&);
	void track(call_handle, transfer_id);
	transfer_id start(std::unique_ptr<transfer>);
	void finish_if_done(transfer_id);

private:
	std::shared_ptr<sftp_client_callback> next_;
	std::map<call_handle, call_completion> calls_;
	std::map<call_handle, transfer_id> owners_;
	std::map<transfer_id, std::unique_ptr<transfer>> transfers_;
	transfer_id next_id_{};
};

}

#endif
