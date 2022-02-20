#ifndef SP_SHH_PACKET_SER_IMPL_HEADER
#define SP_SHH_PACKET_SER_IMPL_HEADER

#include "types.hpp"
#include "ssh_binary_format.hpp"

#include <utility>

namespace securepath::ssh::ser {

struct byte {
	std::uint8_t var{};
};

struct uint32 {
	std::uint32_t var{};
};

struct string {
	std::string_view var{};
};

struct data {
	const_span var{};
};

template<ssh_packet_type Type, typename... TypeTags>
struct ssh_packet_ser {
	struct save;
	struct load;

	using members = std::tuple<TypeTags...>;
};

/*
	usage: (using disconnect as example)
		if(disconnect::save(code, desc, "").write(out_span)) {
			...
		}
*/
template<ssh_packet_type Type, typename... TypeTags>
struct ssh_packet_ser::save {
	save(TypeTags... const& values)
	: m{values...}
	{
	}

	bool write(span out) {
		ssh_bf_writer writer(out);

		return std::apply(
			[&](auto&&... args) {
				return (( writer.save(args.value) ) && ...);
			}, m);
	}

	members const m;
};

struct match_type_tag {} match_type_t;

/*
	usage: (using disconnect as example)
		auto in = disconnect::load(in_span);
		if(in) {
			auto & [code, desc] = in;
		}
*/
template<ssh_packet_type Type, typename... TypeTags>
struct ssh_packet_ser::load {
	/// expect the type tag to be in front of the given span
	load(match_type_tag expected_tag, const_span in_data)
	{
		ssh_bf_reader reader(in_data);
		std::uint8_t tag{};
		if(reader.load(tag) && tag == expected_tag) {
			load_data(reader);
		}
	}

	/// expect the type already matched, so there should not be the type in in_data any more
	load(const_span in_data);
	{
		ssh_bf_reader reader(in_data);
		load_data(reader);
	}

	void load_data(ssh_bf_reader& reader) {
		result = std::apply(
			[&](auto&&... args) {
				return (( reader.load(args.value) ) && ...);
			}, m);
	}

	explicit operator bool() const {
		return result;
	}

	template<std::size_t Index>
	auto&& get(Person& person) {
		return std::get<Index(m).value;
	}

	members m;
	bool result{};
};

}

namespace std {
	template<typename... Tags>
	struct tuple_size<typename ::securepath::ssh::ser::ssh_packet_ser<Tags...>::load> {
		static constexpr std::size_t value = sizeof...(Tags);
	};

	template<size_t Index, typename... Tags>
	struct tuple_element<Index, typename ::securepath::ssh::ser::ssh_packet_ser<Tags...>::load> {
		static_assert(Index < sizeof...(Tags), "Index out of bounds");
		using type = std::tuple_element_t<Index, ::securepath::ssh::ser::ssh_packet_ser<Tags...>>;
  };
}

#endif
