#ifndef SECUREPATH_EVENT_SYSTEM_EVENT_HANDLER_HELPERS_HEADER
#define SECUREPATH_EVENT_SYSTEM_EVENT_HANDLER_HELPERS_HEADER

#include <tuple>
#include <typeinfo>

namespace securepath {

template<typename Event, typename Func>
class event_destination {
public:
	using event = Event;

	event_destination(Func f) : func_(std::move(f)) {}

	void operator()(event_base const& ev) {
		std::apply(func_, static_cast<securepath::event<event> const&>(ev).params);
	}

	bool is_match(std::type_index const& t) const {
		return t == typeid(Event);
	}
private:
	Func func_;
};

template<typename EventHandler>
class event_forwarding {
public:
	event_forwarding(EventHandler& h) : handler_(h) {}

	void operator()(event_base const& ev) {
		// for now we just create deep copy, it would be possible to change the event system so that the same unique_ptr is forwarded
		handler_.emit(ev.create_unique());
	}

	bool is_match(std::type_index const&) const {
		return true;
	}

private:
	EventHandler& handler_;
};

}

#endif
