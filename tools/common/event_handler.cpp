#include "event_handler.hpp"
#include "event_loop.hpp"

namespace securepath {

bool event_handler_base::is_active() const {
	return active_;
}

void event_handler_base::disable() {
	active_ = false;
}

event_handler::event_handler(securepath::event_loop& l)
: loop_(l)
{
}

void event_handler::stop_handler() {
	loop_.remove_receiver(this);
}

void event_handler::emit(std::unique_ptr<event_base> ev) {
	loop_.emit(this, std::move(ev));
}

timer_handle event_handler::start_timer(duration d, bool single_shot) {
	return loop_.start_timer(this, d, single_shot);
}

void event_handler::stop_timer(timer_handle h) {
	loop_.stop_timer(h);
}

event_loop& event_handler::event_loop() const {
	return loop_;
}

}

