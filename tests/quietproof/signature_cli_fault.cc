// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Test-only POSIX fault interposition. No production fault controls are added.
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
extern "C" int fsync(int fd) {
  const char* mode = std::getenv("QUIETPROOF_TEST_FILE_FAULT");
  if (mode && std::strcmp(mode, "io") == 0) { errno = EIO; return -1; }
  if (mode && std::strcmp(mode, "term") == 0) raise(SIGTERM);
  if (mode && std::strcmp(mode, "int") == 0) raise(SIGINT);
  const auto real = reinterpret_cast<int(*)(int)>(dlsym(RTLD_NEXT, "fsync"));
  return real(fd);
}
extern "C" int link(const char* from, const char* to) {
  const char* mode = std::getenv("QUIETPROOF_TEST_FILE_FAULT");
  if (mode && std::strcmp(mode, "race") == 0) {
    const int fd = open(to, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) { (void)write(fd, "retained", 8); close(fd); }
  }
  const auto real = reinterpret_cast<int(*)(const char*, const char*)>(dlsym(RTLD_NEXT, "link"));
  return real(from, to);
}
