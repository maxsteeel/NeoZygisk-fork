#include "event_loop.hpp"

#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

#include "daemon.hpp"
#include "logging.hpp"

bool EventLoop::Init() {
    epoll_fd_ = UniqueFd(epoll_create1(EPOLL_CLOEXEC));
    
    if (epoll_fd_ == -1) {
        PLOGE("create epoll fd");
        return false;
    }
    return true;
}

void EventLoop::Stop() { running = false; }

void EventLoop::Loop() {
    running = true;
    constexpr int MAX_EVENTS = 32;
    struct epoll_event events[MAX_EVENTS];

    while (running) {
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno != EINTR) {
                PLOGE("epoll_wait");
            }
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            EventHandler *handler = static_cast<EventHandler *>(events[i].data.ptr);
            handler->handler_fn(*this, events[i].events, handler->context);
            if (!running) break;
        }
    }
}

bool EventLoop::RegisterHandler(EventHandler *handler, uint32_t events) {
    struct epoll_event ev = {};
    ev.events = events;
    ev.data.ptr = handler;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, handler->fd, &ev) == -1) {
        PLOGE("add event handler");
        return false;
    }
    return true;
}
