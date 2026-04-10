// Async utilities implementation — Sleeper and Semaphore.
// Sleeper wraps a uv_timer_t with a resume() waker (JS sleeper.js).
// Semaphore serializes async sections over the libuv event loop.

#include "hyperdht/async_utils.hpp"

namespace hyperdht {
namespace async_utils {

// ---------------------------------------------------------------------------
// Sleeper
// ---------------------------------------------------------------------------

Sleeper::Sleeper(uv_loop_t* loop) : loop_(loop) {
    timer_ = new uv_timer_t;
    uv_timer_init(loop_, timer_);
    timer_->data = this;
}

Sleeper::~Sleeper() {
    cancel();
    if (timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(timer_))) {
        timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
    }
    timer_ = nullptr;
}

void Sleeper::pause(uint64_t ms, Callback cb) {
    // If a previous pause is active, fire its callback first (JS behavior)
    if (timer_active_) {
        trigger();
    }

    cb_ = std::move(cb);
    timer_active_ = true;
    uv_timer_start(timer_, on_timer, ms, 0);
}

void Sleeper::resume() {
    if (timer_active_ && timer_) {
        uv_timer_stop(timer_);
        trigger();
    }
}

void Sleeper::cancel() {
    if (timer_active_ && timer_) {
        uv_timer_stop(timer_);
        timer_active_ = false;
        cb_ = nullptr;
    }
}

void Sleeper::trigger() {
    timer_active_ = false;
    auto cb = std::move(cb_);
    cb_ = nullptr;
    if (cb) cb();
}

void Sleeper::on_timer(uv_timer_t* handle) {
    auto* self = static_cast<Sleeper*>(handle->data);
    self->trigger();
}

// ---------------------------------------------------------------------------
// Semaphore
// ---------------------------------------------------------------------------

Semaphore::Semaphore(int limit) : limit_(limit) {}

void Semaphore::wait(WaitCallback cb) {
    if (destroyed_) {
        if (cb) cb(false);
        return;
    }

    if (active_ < limit_ && waiting_.empty()) {
        active_++;
        if (cb) cb(true);
        return;
    }

    // Queue the waiter
    waiting_.push_back(std::move(cb));
}

void Semaphore::signal() {
    if (active_ > 0) active_--;

    // Dequeue waiters while capacity available
    while (active_ < limit_ && !waiting_.empty() && !destroyed_) {
        active_++;
        auto cb = std::move(waiting_.front());
        waiting_.pop_front();
        if (cb) cb(true);
    }

    // Check flush condition
    if (active_ == 0 && flush_cb_) {
        auto cb = std::move(flush_cb_);
        flush_cb_ = nullptr;
        cb(true);
    }
}

void Semaphore::flush(WaitCallback cb) {
    if (destroyed_) {
        if (cb) cb(false);
        return;
    }

    if (active_ == 0) {
        if (cb) cb(true);
        return;
    }

    flush_cb_ = std::move(cb);
}

void Semaphore::destroy() {
    destroyed_ = true;
    active_ = 0;

    // Reject all waiting
    while (!waiting_.empty()) {
        auto cb = std::move(waiting_.back());
        waiting_.pop_back();
        if (cb) cb(false);
    }

    // Reject pending flush
    if (flush_cb_) {
        auto cb = std::move(flush_cb_);
        flush_cb_ = nullptr;
        cb(false);
    }
}

}  // namespace async_utils
}  // namespace hyperdht
