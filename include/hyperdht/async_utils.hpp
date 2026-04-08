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
    uv_timer_t timer_;
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

}  // namespace async_utils
}  // namespace hyperdht
