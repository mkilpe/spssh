#ifndef SECUREPATH_EVENT_SYSTEM_EVENT_HANDLER_HEADER
#define SECUREPATH_EVENT_SYSTEM_EVENT_HANDLER_HEADER

#include "event.hpp"
#include "event_handler_helpers.hpp"
#include <cassert>
#include <chrono>
#include <functional>
#include <memory>

namespace securepath {

/// this is base for handling dedicated event for one single receiver (as opposite of broadcast event)
class event_handler_base {
public:
	virtual ~event_handler_base() {}
	virtual void handle_event(std::unique_ptr<event_base>) = 0;

	///these are used by implementation to allow safe destruction, the implementation has to handle mutually exclusive access
	bool is_active() const;
	void disable();
private:
	bool active_{true};
};

class event_handler;
class event_loop;

class event_handler : public event_handler_base {
public:
	// just for derived classes
	using event_base = securepath::event_base;
	using duration = std::chrono::milliseconds;

	event_handler(securepath::event_loop&);
	event_handler(event_handler const&) = delete;
	event_handler& operator=(event_handler const&) = delete;

	/// this needs to be called on the most derived class' destructor
	void stop_handler();

	template<typename Event, typename... Args>
	void emit(Args&&... args);
	void emit(std::unique_ptr<event_base>);

	timer_handle start_timer(duration, bool single_shot);
	void stop_timer(timer_handle);

	securepath::event_loop& event_loop() const;

protected:
	template<typename Arg, typename... Args>
	bool dispatch(event_base const&, Arg&& arg, Args&&... args);

	template<typename Event, typename Func>
	auto event_dest(Func f) {
		return event_destination<Event, Func>(std::move(f));
	}
	template<typename Event, typename Ret, typename Class, typename... Args>
	auto event_dest(Ret (Class::*member)(Args...)) {
		auto f = [this, member](auto&&... args) { (static_cast<Class*>(this)->*member)(std::forward<decltype(args)>(args)...); };
		return event_destination<Event, decltype(f)>(std::move(f));
	}
	template<typename Handler>
	auto event_forward(Handler& handler) {
		return event_forwarding<Handler>(handler);
	}

private:

	securepath::event_loop& loop_;
};

template<typename Event, typename... Args>
void event_handler::emit(Args&&... args) {
	std::unique_ptr<event_base> ev(new event<Event>(std::forward<Args>(args)...));
	emit(std::move(ev));
}

template<typename Arg, typename... Args>
bool event_handler::dispatch(event_base const& ev, Arg&& arg, Args&&... args) {
	if(arg.is_match(ev.type)) {
		arg(ev);
		return true;
	} else {
		if constexpr(sizeof...(args) != 0) {
			return dispatch(ev, std::forward<Args>(args)...);
		} else {
			return false;
		}
	}
}

}

#endif
