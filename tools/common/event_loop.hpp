#ifndef SECUREPATH_EVENT_SYSTEM_EVENT_LOOP_HEADER
#define SECUREPATH_EVENT_SYSTEM_EVENT_LOOP_HEADER

#include "event.hpp"
#include "ssh/common/logger.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

namespace securepath {

class event_handler_base;
using receiver = event_handler_base*;

class event_loop {
public:
	using duration = std::chrono::milliseconds;

	virtual ~event_loop() {}
	virtual void emit(receiver, std::unique_ptr<event_base> ev) = 0;
	virtual void remove_receiver(receiver) = 0;
	virtual timer_handle start_timer(receiver, duration, bool single_shot) = 0;
	virtual void stop_timer(timer_handle) = 0;
};

class basic_event_loop : public event_loop {
public:
	basic_event_loop(logger&);

	/// Emit event to a receiver
	void emit(receiver, std::unique_ptr<event_base> ev) override;
	/// Remove all events for this receiver and wait if the event handler is currently called for this receiver (unless same thread as calling this function)
	void remove_receiver(receiver) override;
	/// Start a timer with duration in milliseconds. If timer is single shot, it is removed after triggering once
	timer_handle start_timer(receiver, duration, bool single_shot) override;
	/// Stop timer
	void stop_timer(timer_handle) override;

protected:
	struct event_holder {
		std::unique_ptr<event_base> event;
		receiver handler;
	};
	void handle_event(std::unique_lock<std::mutex>& l, receiver, std::unique_ptr<event_base>);
	bool process_single_event(std::unique_lock<std::mutex>&);

	using clock_type = std::chrono::steady_clock;
	struct timer_holder {
		timer_handle id;
		clock_type::time_point next_trigger;
		clock_type::duration interval;
		receiver handler;
	};
	void update_next_trigger(clock_type::time_point t);
	bool process_timers(std::unique_lock<std::mutex>&);

protected:
	logger& log_;

	std::deque<event_holder> events_;
	receiver active_handler_{};

	std::deque<timer_holder> timers_;
	clock_type::time_point next_trigger_;
	timer_handle last_timer_handle_{};

	std::mutex mutex_;
	std::condition_variable cond_;

	bool quit_{};
	std::thread::id my_thread_id_;
};

struct spawn_thread_type {} constexpr spawn_thread;

class single_thread_event_loop : public basic_event_loop {
public:
	single_thread_event_loop(logger&, spawn_thread_type);
	single_thread_event_loop(logger&);
	~single_thread_event_loop();

	void stop();

	void thread_entry();

private:
	std::thread thread_;
};

}

#endif
