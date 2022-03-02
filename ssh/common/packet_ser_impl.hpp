#ifndef SP_SHH_PACKET_SER_IMPL_HEADER
#define SP_SHH_PACKET_SER_IMPL_HEADER

#include "packet_ser.hpp"
#include "ssh_binary_util.hpp"

#include <tuple>
#include <utility>

namespace securepath::ssh::ser {

struct boolean {
	using type = bool;
	type value{};
	static constexpr std::size_t static_size = 1;
	std::size_t size() const {	return static_size; }
};

struct byte {
	using type = std::uint8_t;
	type value{};
	static constexpr std::size_t static_size = 1;
	std::size_t size() const {	return static_size; }
};

struct uint32 {
	using type = std::uint32_t;
	type value{};
	static constexpr std::size_t static_size = 4;
	std::size_t size() const {	return static_size; }
};

struct string {
	using type = std::string_view;
	type value{};
	static constexpr std::size_t static_size = 4;
	std::size_t size() const {	return static_size + value.size(); }
};

struct data {
	using type = const_span;
	type value{};
	static constexpr std::size_t static_size = 4;
	std::size_t size() const {	return static_size + value.size(); }
};

template<ssh_packet_type Type, typename... TypeTags> struct ssh_packet_ser_load;

template<ssh_packet_type Type, typename... TypeTags>
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
	static constexpr ssh_packet_type packet_type = Type;

	static constexpr std::size_t static_size = std::apply(
		[](auto&&... args) {
			return ((args.static_size) + ...);
		});
};


template<ssh_packet_type Type, typename... TypeTags>
struct ssh_packet_ser<Type, TypeTags...>::save {
	save(TypeTags::type const&... values)
	: m_{values...}
	{
	}

	bool write(span out) {
		ssh_bf_writer writer(out);

		writer.save(std::uint8_t(Type));

		bool ret = std::apply(
			[&](auto&&... args) {
				return (( writer.save(args.value) ) && ...);
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

struct match_type_tag {} match_type_t;

template<ssh_packet_type Type, typename... TypeTags>
struct ssh_packet_ser_load {
	using members = std::tuple<TypeTags...>;

	/// expect the type tag to be in front of the given span
	ssh_packet_ser_load(match_type_tag, const_span in_data)
	{
		ssh_bf_reader reader(in_data);
		std::uint8_t tag{};

		if(reader.load(tag) && tag == Type) {
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
		return std::get<Index>(m_).value;
	}

private:
	void load_data(ssh_bf_reader& reader) {
		result_ = std::apply(
			[&](auto&&... args) {
				return (( reader.load(args.value) ) && ...);
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
	template<::securepath::ssh::ssh_packet_type Type, typename... Tags>
	struct tuple_size<::securepath::ssh::ser::ssh_packet_ser_load<Type, Tags...>> {
		static constexpr std::size_t value = sizeof...(Tags);
	};

	template<size_t Index, ::securepath::ssh::ssh_packet_type Type, typename... Tags>
	struct tuple_element<Index, ::securepath::ssh::ser::ssh_packet_ser_load<Type, Tags...>> {
		static_assert(Index < sizeof...(Tags), "Index out of bounds");
		using type = std::tuple_element_t<Index, typename ::securepath::ssh::ser::ssh_packet_ser<Type, Tags...>::members>::type;
  };
}

#endif
