#ifndef SP_SSH_SFTP_PACKET_SER_IMPL_HEADER
#define SP_SSH_SFTP_PACKET_SER_IMPL_HEADER

#include "ssh/core/packet_ser.hpp"

namespace securepath::ssh::sftp {

template<std::uint8_t Type, typename... TypeTags> struct sftp_packet_ser_save;
template<std::uint8_t Type, typename... TypeTags> struct sftp_packet_ser_load;

/// see core/packet_ser_impl.hpp for usage
template<std::uint8_t Type, typename... TypeTags>
struct sftp_packet_ser {
	using save = sftp_packet_ser_save<Type, TypeTags...>;
	using load = sftp_packet_ser_load<Type, TypeTags...>;

	using members = std::tuple<TypeTags...>;
	static constexpr std::uint8_t packet_type = Type;
};


template<std::uint8_t Type, typename... TypeTags>
struct sftp_packet_ser_save : private ser::packet_ser_save<Type, TypeTags...> {

	using base = ser::packet_ser_save<Type, TypeTags...>;
	using base::base;

	bool write(span out) {
		ssh_bf_writer writer(out);
		return write(writer);
	}

	bool write(ssh_bf_writer& writer) {
		// write the length of the package, type tag + data
		writer.write(std::uint32_t(base::size()));
		return base::write(writer);
	}

	std::size_t size() const {
		// length ´+ type tag size + rest of the packet size
		return ser::uint32::static_size + base::size();
	}

	using base::serialised_size;
};

template<std::uint8_t Type, typename... TypeTags>
struct sftp_packet_ser_load : private ser::packet_ser_load<Type, TypeTags...> {
	using base = ser::packet_ser_load<Type, TypeTags...>;

	/// expect the length and type tag to be in front of the given span
	sftp_packet_ser_load(ser::match_type_tag, const_span in_data)
	: base(in_data)
	{
		std::uint32_t length{};
		if(this->reader_.read(length) && in_data.size() >= length+ser::uint32::static_size) {
			this->load_data_with_tag();
		}
	}

	/// expect the type already matched, so there should not be the type tag in in_data any more
	sftp_packet_ser_load(const_span in_data)
	: base(in_data)
	{
		this->load_data();
	}

	using base::operator bool;
	using base::get;
	using base::reader;
	using base::size;
};

}

namespace std {
	template<uint8_t  Type, typename... Tags>
	struct tuple_size<::securepath::ssh::sftp::sftp_packet_ser_load<Type, Tags...>> {
		static constexpr std::size_t value = sizeof...(Tags);
	};

	template<size_t Index, uint8_t Type, typename... Tags>
	struct tuple_element<Index, ::securepath::ssh::sftp::sftp_packet_ser_load<Type, Tags...>> {
		static_assert(Index < sizeof...(Tags), "Index out of bounds");
		using type = std::tuple_element_t<Index, typename ::securepath::ssh::ser::packet_ser_load<Type, Tags...>::members>::type;
  };
}

#endif