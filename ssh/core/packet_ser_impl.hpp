#ifndef SP_SHH_PACKET_SER_IMPL_HEADER
#define SP_SHH_PACKET_SER_IMPL_HEADER

#include "packet_ser.hpp"
#include "ssh_binary_util.hpp"
#include "protocol_helpers.hpp"

#include <vector>
#include <tuple>
#include <utility>

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


template<std::uint8_t Type, typename... TypeTags> struct ssh_packet_ser_load;

template<std::uint8_t Type, typename... TypeTags>
struct ssh_packet_ser {
	/*
		usage: (using disconnect as example)
			if(disconnect::save(code, desc, "").write(out_span)) {
				...
			}
	*/
	struct save;

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

	static constexpr std::size_t static_size = std::apply(
		[](auto&&... args) {
			return ((args.static_size) + ...);
		});
};


template<std::uint8_t Type, typename... TypeTags>
struct ssh_packet_ser<Type, TypeTags...>::save {
	save(TypeTags::type const&... values)
	: m_{values...}
	{
	}

	bool write(span out) {
		ssh_bf_writer writer(out);

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
				return (( args.size() ) + ...);
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

struct match_type_tag {} constexpr match_type_t;

template<std::uint8_t Type, typename... TypeTags>
struct ssh_packet_ser_load {
	using members = std::tuple<TypeTags...>;

	/// expect the type tag to be in front of the given span
	ssh_packet_ser_load(match_type_tag, const_span in_data)
	{
		ssh_bf_reader reader(in_data);
		std::uint8_t tag{};

		if(reader.read(tag) && tag == Type) {
			load_data(reader);
		}
	}

	/// expect the type already matched, so there should not be the type tag in in_data any more
	ssh_packet_ser_load(const_span in_data)
	{
		ssh_bf_reader reader(in_data);
		load_data(reader);
	}

	explicit operator bool() const {
		return result_;
	}

	template<std::size_t Index>
	auto&& get() {
		return std::get<Index>(m_).view();
	}

private:
	void load_data(ssh_bf_reader& reader) {
		result_ = std::apply(
			[&](auto&&... args) {
				return (( args.read(reader) ) && ...);
			}, m_);

		if(result_) {
			size_ = reader.used_size();
		}
	}

private:
	members m_;
	bool result_{};
	std::size_t size_{};
};

}

namespace std {
	template<uint8_t  Type, typename... Tags>
	struct tuple_size<::securepath::ssh::ser::ssh_packet_ser_load<Type, Tags...>> {
		static constexpr std::size_t value = sizeof...(Tags);
	};

	template<size_t Index, uint8_t Type, typename... Tags>
	struct tuple_element<Index, ::securepath::ssh::ser::ssh_packet_ser_load<Type, Tags...>> {
		static_assert(Index < sizeof...(Tags), "Index out of bounds");
		using type = std::tuple_element_t<Index, typename ::securepath::ssh::ser::ssh_packet_ser<Type, Tags...>::members>::type;
  };
}

#endif
