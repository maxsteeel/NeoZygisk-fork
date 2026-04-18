#pragma once

namespace companion {

// The main entry point for a companion process.
void entry(int fd);

} // namespace companion

namespace zygiskd_main {

// The main function for the zygiskd daemon.
int main();

} // namespace zygiskd_main
