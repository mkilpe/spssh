#include "event_loop.hpp"
#include "event_handler.hpp"

#include <algorithm>
#include <cassert>

namespace securepath {

basic_event_loop::basic_event_loop(logger& l)
: log_(l)
{
}

void basic_event_loop::emit(receiver r, std::unique_ptr<event_base> ev) {
	assert(r);
	assert(ev);
	std::unique_lock l{mutex_};
	if(!quit_ && r->is_active()) {
		if(events_.empty()) {
			cond_.notify_one();
		}
		events_.push_back(event_holder{std::move(ev), r});
	}
}

void basic_event_loop::remove_receiver(receiver r) {
	std::unique_lock l{mutex_};
	r->disable();

	auto has_receiver = [&](auto const& h) {return h.handler == r;};

	events_.erase(std::remove_if(events_.begin(), events_.end(), has_receiver), events_.end());
	timers_.erase(std::remove_if(timers_.begin(), timers_.end(), has_receiver), timers_.end());

	if(active_handler_ == r && my_thread_id_ != std::this_thread::get_id()) {
		while(active_handler_ == r) {
			l.unlock();
			std::this_thread::yield();
			l.lock();
		}
	}
}

timer_handle basic_event_loop::start_timer(receiver r, duration dur, bool single_shot) {
	assert(r);
	timer_handle ret{};
	std::unique_lock l{mutex_};
	if(!quit_ && r->is_active()) {
		ret = ++last_timer_handle_;
		auto trigger = clock_type::now() + dur;
		timers_.push_back(timer_holder{ret, trigger, single_shot ? duration{} : dur, r});

		if(events_.empty() && (next_trigger_ == clock_type::time_point{} || trigger < next_trigger_)) {
			cond_.notify_one();
		}

		update_next_trigger(trigger);
	}
	return ret;
}

void basic_event_loop::stop_timer(timer_handle id) {
	std::unique_lock l{mutex_};
	auto it = std::find_if(timers_.begin(), timers_.end(), [&](auto const& h) {return h.id == id;});
	if(it != timers_.end()) {
		timers_.erase(it);
		if(timers_.empty()) {
			next_trigger_ = clock_type::time_point{};
		}
	}
}

void basic_event_loop::handle_event(std::unique_lock<std::mutex>& l, receiver handler, std::unique_ptr<event_base> event) {
	active_handler_ = handler;
	l.unlock();
	try {
		handler->handle_event(std::move(event));
	} catch(std::exception const& ex) {
		log_.log(logger::error, "exception in event handling: {}", ex.what());
	} catch(...) {
		log_.log(logger::error, "unknown exception in event handling");
	}
	l.lock();
	active_handler_ = nullptr;
}

void basic_event_loop::update_next_trigger(clock_type::time_point t) {
	if(next_trigger_ == clock_type::time_point{} || t < next_trigger_) {
		next_trigger_ = t;
	}
}

bool basic_event_loop::process_timers(std::unique_lock<std::mutex>& l) {
	auto now = clock_type::now();
	if(next_trigger_ == clock_type::time_point{} || now < next_trigger_) {
		return false;
	}

	next_trigger_ = clock_type::time_point{};
	auto it = timers_.begin();
	for(; it != timers_.end() && now < it->next_trigger; ++it) {
		update_next_trigger(it->next_trigger);
	}

	bool ret = it != timers_.end();
	if(ret) {
		auto itc = it;
		for(++itc; itc != timers_.end(); ++itc ) {
			update_next_trigger(itc->next_trigger);
		}
		auto id = it->id;
		auto h = it->handler;
		if(it->interval != duration{}) {
			it->next_trigger = now + it->interval;
			update_next_trigger(it->next_trigger);
		} else {
			timers_.erase(it);
		}
		handle_event(l, h, std::make_unique<event<timer_event>>(id));
	}
	return ret;
}

bool basic_event_loop::process_single_event(std::unique_lock<std::mutex>& l) {
	bool ret = process_timers(l);
	if(!ret && !events_.empty()) {
		auto h = std::move(events_.front());
		events_.pop_front();
		handle_event(l, h.handler, std::move(h.event));
	}
	return ret || !events_.empty();
}

single_thread_event_loop::single_thread_event_loop(logger& l)
: basic_event_loop(l)
{

}

single_thread_event_loop::single_thread_event_loop(logger& l, spawn_thread_type)
: basic_event_loop(l)
, thread_([this]{this->thread_entry();})
{
}

single_thread_event_loop::~single_thread_event_loop()
{
	stop();
}

void single_thread_event_loop::stop() {
	{
		std::unique_lock l{mutex_};
		quit_ = true;
		cond_.notify_one();
	}
	if(thread_.joinable()) {
		thread_.join();
	}
	events_.clear();
	timers_.clear();
}

void single_thread_event_loop::thread_entry() {
	std::unique_lock l{mutex_};
	my_thread_id_ = std::this_thread::get_id();

	while(!quit_) {
		auto more = process_single_event(l);
		if(!quit_ && !more) {
			if(next_trigger_ != clock_type::time_point{}) {
				cond_.wait_until(l, next_trigger_);
			} else {
				cond_.wait(l);
			}
		}
	}
}

}
