#ifndef SECUREPATH_EVENT_SYSTEM_EVENT_HEADER
#define SECUREPATH_EVENT_SYSTEM_EVENT_HEADER

#include <cstdint>
#include <memory>
#include <tuple>
#include <type_traits>
#include <typeindex>

namespace securepath {

class event_base {
public:
	event_base(std::type_index index) : type(index) {}
	virtual ~event_base() {}

	/// Makes a deep copy of the event, used for broadcast versus normal event system interaction
	virtual std::unique_ptr<event_base> create_unique() const = 0;
public:
	/// The event type index to match the event for correct handler
	std::type_index const type;
};

template<typename T>
struct param_deduce;

template<typename... P>
struct param_deduce<void(P...)> {
	using tuple_type = std::tuple<std::decay_t<P>...>;
	static constexpr std::size_t const size = sizeof...(P);
};

template<typename Event>
class event : public event_base {
public:
	using event_type = Event;
	using deduce = param_deduce<typename Event::type>;
	using params_type = typename deduce::tuple_type;
	static constexpr std::size_t const size = deduce::size;

	template<typename... Args>
	event(Args&&... args)
	: event_base(typeid(event_type))
	, params(std::forward<Args>(args)...)
	{}

	event(event const&) = default;

	virtual std::unique_ptr<event_base> create_unique() const {
		return std::make_unique<event>(params);
	}

	params_type params;
};

using timer_handle = std::uint64_t;
struct timer_event {
	typedef void type(timer_handle);
};

}

#endif
