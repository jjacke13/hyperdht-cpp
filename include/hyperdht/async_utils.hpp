#pragma once

// Async utilities for the single-threaded libuv event loop.
//
// Sleeper — interruptible timer (matches JS hyperdht/lib/sleeper.js)
//   pause(ms, cb): starts a timer, calls cb when done or resumed
//   resume(): cancels current timer and fires cb immediately
//
// Semaphore — async concurrency limiter (matches JS hyperdht/lib/semaphore.js)
//   wait(cb): acquire a permit, call cb(true) when acquired or cb(false) if destroyed
//   signal(): release a permit, dequeue next waiter
//   flush(cb): call cb when all active permits are released
//   destroy(): reject all waiters, reset

#include <cstdint>
#include <deque>
#include <functional>

#include <uv.h>

namespace hyperdht {
namespace async_utils {

// ---------------------------------------------------------------------------
// Sleeper — interruptible timer
// ---------------------------------------------------------------------------

class Sleeper {
public:
    explicit Sleeper(uv_loop_t* loop);
    ~Sleeper();

    Sleeper(const Sleeper&) = delete;
    Sleeper& operator=(const Sleeper&) = delete;

    // Start a timer. When it fires (or resume() is called), cb is invoked.
    // If a previous pause is active, it is resumed (cb fired) before starting new.
    using Callback = std::function<void()>;
    void pause(uint64_t ms, Callback cb);

    // Cancel current timer and fire cb immediately.
    void resume();

    // Is a pause currently active?
    bool is_paused() const { return timer_active_; }

    // Stop timer without firing callback. For cleanup.
    void cancel();

private:
    uv_loop_t* loop_;
    uv_timer_t* timer_ = nullptr;  // Heap-allocated for safe uv_close
    Callback cb_;
    bool timer_active_ = false;
    bool closing_ = false;

    void trigger();
    static void on_timer(uv_timer_t* handle);
};

// ---------------------------------------------------------------------------
// Semaphore — async concurrency limiter
// ---------------------------------------------------------------------------

class Semaphore {
public:
    // limit: max concurrent permits (JS default: 1, connect.js uses 2)
    explicit Semaphore(int limit = 1);

    // Request a permit. Calls cb(true) when acquired, cb(false) if destroyed.
    using WaitCallback = std::function<void(bool acquired)>;
    void wait(WaitCallback cb);

    // Release a permit and dequeue next waiter.
    void signal();

    // Call cb(true) when all active permits are released. cb(false) if destroyed.
    void flush(WaitCallback cb);

    // Destroy: reject all waiters and pending flush.
    void destroy();

    int active() const { return active_; }
    int limit() const { return limit_; }
    bool is_destroyed() const { return destroyed_; }
    size_t waiting() const { return waiting_.size(); }

private:
    int limit_;
    int active_ = 0;
    bool destroyed_ = false;
    std::deque<WaitCallback> waiting_;
    WaitCallback flush_cb_;
};

// ---------------------------------------------------------------------------
// UvTimer — RAII wrapper for uv_timer_t
// ---------------------------------------------------------------------------
// Owns a heap-allocated uv_timer_t. Destructor stops and closes the handle.
// Eliminates the manual new/delete pattern that risks leaks when close
// callbacks don't fire or fire in unexpected order.
//
// Usage:
//   UvTimer timer(loop);
//   timer.start([](){ /* fired */ }, 5000);
//   timer.stop();        // optional — destructor handles it
//   // timer goes out of scope → handle closed automatically

class UvTimer {
public:
    using Callback = std::function<void()>;

    explicit UvTimer(uv_loop_t* loop) : loop_(loop) {
        handle_ = new uv_timer_t;
        uv_timer_init(loop_, handle_);
        handle_->data = this;
    }

    ~UvTimer() {
        if (!handle_) return;
        uv_timer_stop(handle_);
        handle_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(handle_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        handle_ = nullptr;
    }

    UvTimer(const UvTimer&) = delete;
    UvTimer& operator=(const UvTimer&) = delete;
    UvTimer(UvTimer&&) = delete;
    UvTimer& operator=(UvTimer&&) = delete;

    void start(Callback cb, uint64_t timeout_ms, uint64_t repeat_ms = 0) {
        cb_ = std::move(cb);
        uv_timer_start(handle_, on_timer, timeout_ms, repeat_ms);
    }

    void stop() {
        if (handle_) uv_timer_stop(handle_);
        cb_ = nullptr;
    }

    bool is_active() const {
        return handle_ && uv_is_active(reinterpret_cast<const uv_handle_t*>(handle_));
    }

private:
    uv_loop_t* loop_;
    uv_timer_t* handle_;
    Callback cb_;

    static void on_timer(uv_timer_t* t) {
        auto* self = static_cast<UvTimer*>(t->data);
        if (self && self->cb_) self->cb_();
    }
};

}  // namespace async_utils
}  // namespace hyperdht
