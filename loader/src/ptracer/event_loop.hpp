#pragma once

#include <stdint.h>
#include "daemon.hpp"

// Forward declaration
class EventLoop;

typedef void (*EventCallback)(EventLoop &loop, uint32_t event, void* context);

/**
 * @brief An abstract interface for event handlers.
 *
 * Any class that wants to be managed by the EventLoop must implement this
 * interface. It provides a contract for getting a file descriptor to watch
 * and a method to handle events on that descriptor.
 */
struct EventHandler {
    int fd;
    EventCallback handler_fn;
    void* context;
};

class EventLoop {
public:
    EventLoop &operator=(const EventLoop &) = delete;

    bool Init();
    void Stop();
    void Loop();
    bool RegisterHandler(EventHandler *handler, uint32_t events);

private:
    UniqueFd epoll_fd_;
    bool running;
};
