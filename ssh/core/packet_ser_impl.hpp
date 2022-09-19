#ifndef SP_SHH_PACKET_SER_IMPL_HEADER
#define SP_SHH_PACKET_SER_IMPL_HEADER

#include "packet_ser.hpp"
#include "ssh_binary_util.hpp"
#include "protocol_helpers.hpp"

#include <vector>
#include <tuple>
#include <utility>
#include <type_traits>

namespace securepath::ssh::ser {

template<typename Type>
struct type_base {
	using type = Type;
	type data{};

	type_base() = default;
	type_base(type t) : data(t) {};

	bool read(ssh_bf_reader& r) {
		return r.read(data);
	}

	bool write(ssh_bf_writer& w) const {
		return w.write(data);
	}

	type& view() {
		return data;
	}
};

struct boolean : type_base<bool> {
	using type_base::type_base;
	static constexpr std::size_t static_size = 1;
	std::size_t size() const {	return static_size; }
};

struct byte : type_base<std::byte> {
	using type_base::type_base;
	static constexpr std::size_t static_size = 1;
	std::size_t size() const {	return static_size; }
};

struct uint32 : type_base<std::uint32_t> {
	using type_base::type_base;
	static constexpr std::size_t static_size = 4;
	std::size_t size() const {	return static_size; }
};

struct uint64 : type_base<std::uint64_t> {
	using type_base::type_base;
	static constexpr std::size_t static_size = 8;
	std::size_t size() const {	return static_size; }
};

struct mpint : type_base<const_mpint_span> {
	using type_base::type_base;
	static constexpr std::size_t static_size = 4;
	std::size_t size() const {	return encoded_size(data); }
};

struct string : type_base<std::string_view> {
	using type_base::type_base;
	static constexpr std::size_t static_size = 4;
	std::size_t size() const {	return static_size + data.size(); }
};

struct name_list {
	using type = std::vector<std::string_view>;

	name_list() = default;
	name_list(type const& t) : error(!to_string_list(t, data)) {}

	type value{};
	std::string data{};
	bool error{};

	static constexpr std::size_t static_size = 4;
	std::size_t size() const {
		return static_size + data.size();
	}

	bool read(ssh_bf_reader& r) {
		std::string_view in;
		return r.read(in) && parse_string_list(in, value);
	}

	bool write(ssh_bf_writer& w) const {
		return !error && w.write(data);
	}

	type& view() {
		return value;
	}
};

template<std::size_t Size>
struct bytes {
	using type = std::span<std::byte const, Size>;

	// constant size span is not default constructible
	std::optional<type> data{};

	bytes() = default;
	bytes(type t) : data(t) {}

	static constexpr std::size_t static_size = Size;
	std::size_t size() const { return Size; }

	bool read(ssh_bf_reader& r) {
		return r.read(data);
	}

	bool write(ssh_bf_writer& w) const {
		SPSSH_ASSERT(data, "invalid state");
		return w.write(data.value());
	}

	type& view() {
		SPSSH_ASSERT(data, "invalid state");
		return data.value();
	}
};


template<std::uint8_t Type, typename... TypeTags> struct ssh_packet_ser_save;
template<std::uint8_t Type, typename... TypeTags> struct ssh_packet_ser_load;

template<std::uint8_t Type, typename... TypeTags>
struct ssh_packet_ser {
	/*
		usage: (using disconnect as example)
			if(disconnect::save(code, desc, "").write(out_span)) {
				...
			}
	*/
	using save = ssh_packet_ser_save<Type, TypeTags...>;

	/*
	usage: (using disconnect as example)
		auto in = disconnect::load(in_span);
		if(in) {
			auto & [code, desc] = in;
		}
	*/
	using load = ssh_packet_ser_load<Type, TypeTags...>;

	using members = std::tuple<TypeTags...>;
	static constexpr std::uint8_t packet_type = Type;
};

struct packet_ser_save_base {};

template<std::uint8_t Type, typename... TypeTags>
struct packet_ser_save : private packet_ser_save_base {
	using members = std::tuple<TypeTags...>;

	template<typename... Args>
	packet_ser_save(Args&&... args)
	: m_{std::forward<Args>(args)...}
	{
	}

	bool write(ssh_bf_writer& writer) {
		writer.write(std::uint8_t(Type));

		bool ret = std::apply(
			[&](auto&&... args) {
				return (( args.write(writer) ) && ...);
			}, m_);

		if(ret) {
			size_ = writer.used_size();
		}

		return ret;
	}

	/// This can be used to allocate buffer for the write()
	std::size_t size() const {
		// type tag size + rest of the packet size
		return byte::static_size + std::apply(
			[&](auto&&... args) {
				return (( args.size() ) + ... + 0);
			}, m_);
	}

	/// This should return same as size() after write has been called
	std::size_t serialised_size() const {
		return size_;
	}

private:
	members const m_;
	std::size_t size_{};
};

template<std::uint8_t Type, typename... TypeTags>
struct ssh_packet_ser_save : private packet_ser_save<Type, TypeTags...> {
	using base = packet_ser_save<Type, TypeTags...>;
	using base::base;
	using base::write;
	using base::size;
	using base::serialised_size;

	bool write(span out) {
		ssh_bf_writer writer(out);
		return write(writer);
	}
};

struct match_type_tag {} constexpr match_type_t;

template<std::uint8_t Type, typename... TypeTags>
struct packet_ser_load {
	using members = std::tuple<TypeTags...>;

	packet_ser_load(const_span in_data)
	: reader_(in_data)
	{}

	explicit operator bool() const {
		return result_;
	}

	template<std::size_t Index>
	auto&& get() {
		return std::get<Index>(m_).view();
	}

	// this can be used to extract optional data at the end of the packet
	ssh_bf_reader& reader() {
		return reader_;
	}

	std::size_t size() const {
		return size_;
	}

protected:
	void load_data() {
		result_ = std::apply(
			[&](auto&&... args) {
				return (( args.read(reader_) ) && ...);
			}, m_);

		if(result_) {
			size_ = reader_.used_size();
		}
	}

	void load_data_with_tag() {
		std::uint8_t tag{};

		if(reader_.read(tag) && tag == Type) {
			load_data();
		}
	}

public:
	members m_;
	ssh_bf_reader reader_;
	bool result_{};
	std::size_t size_{};
};

template<std::uint8_t Type, typename... TypeTags>
struct ssh_packet_ser_load : private packet_ser_load<Type, TypeTags...> {
	using base = packet_ser_load<Type, TypeTags...>;

	/// expect the type tag to be in front of the given span
	ssh_packet_ser_load(match_type_tag, const_span in_data)
	: base(in_data)
	{
		this->load_data_with_tag();
	}

	/// expect the type already matched, so there should not be the type tag in in_data any more
	ssh_packet_ser_load(const_span in_data)
	: base(in_data)
	{
		this->load_data();
	}

	using base::base;
	using base::operator bool;
	using base::get;
	using base::reader;
	using base::size;
};

template<typename Packet>
struct packet_string_adaptor {
	packet_string_adaptor(Packet& p) : packet_(p) {}

	Packet& packet_;

	static constexpr std::size_t static_size = 4;
	std::size_t size() const {
		return static_size + std::uint32_t(packet_.size());
	}

	bool write(ssh_bf_writer& w) const {
		return w.write(std::uint32_t(packet_.size())) && packet_.write(w);
	}
};

template<typename>
struct transform_args;

template<std::uint8_t Type, typename... TypeTags>
struct transform_args<ssh_packet_ser<Type, TypeTags...>> {
	template<typename... Args>
	static auto save(Args&&... args) {
		return ssh_packet_ser_save<Type,
			std::conditional_t<
				std::is_base_of_v<packet_ser_save_base, std::decay_t<Args>> && std::is_same_v<TypeTags, string>,
					packet_string_adaptor<std::decay_t<Args>>,
					TypeTags
			>...>
			{
				std::forward<Args>(args)...
			};
	}
};

// this is a work around because nested class deduction guidelines not working on g++ 11 and
// implicit deduction guides seems not to work with clang for nested templates
// Creates save-type that can use nested packets to serialise
template<typename Packet, typename... Args>
auto make_packet_saver(Args&&... args) {
	return transform_args<Packet>::save(std::forward<Args>(args)...);
}

}

namespace std {
	template<uint8_t Type, typename... Tags>
	struct tuple_size<::securepath::ssh::ser::ssh_packet_ser_load<Type, Tags...>> {
		static constexpr std::size_t value = sizeof...(Tags);
	};

	template<size_t Index, uint8_t Type, typename... Tags>
	struct tuple_element<Index, ::securepath::ssh::ser::ssh_packet_ser_load<Type, Tags...>> {
		static_assert(Index < sizeof...(Tags), "Index out of bounds");
		using type = std::tuple_element_t<Index, typename ::securepath::ssh::ser::packet_ser_load<Type, Tags...>::members>::type;
  };
}

#endif
