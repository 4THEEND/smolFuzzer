// syscall_mutator.hpp - the "syscall" mutator: inputs are win32k syscall
// programs (see syscall_program.hpp) instead of opaque bytes.
//
// The mutator registers itself under the name "syscall"; select it like any
// other one. It works on its own, and draws real arguments from a
// sysmon::ArgPool once you hand it one:
//
//   sysmon::ArgPool   pool;        // filled from decoded calls
//   std::shared_mutex poolGuard;   // only needed if the pool changes while fuzzing
//   setSyscallArgPool(&pool, &poolGuard);
//
// ArgPool is not thread-safe. If anything adds to the pool while agents are
// mutating, pass a guard and hold it exclusively around pool.Add()/Clear();
// the mutator holds it shared for the duration of one mutate() call. If the
// pool is complete before fuzzing starts, no guard is needed.
#pragma once

#include <cstddef>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

namespace sysmon {
class ArgPool;
}

// `pool` (and `guard`, if given) must outlive all mutators. Pass nullptr to
// detach. Applies to every "syscall" mutator in the process.
void setSyscallArgPool(const sysmon::ArgPool* pool, std::shared_mutex* guard = nullptr);

// Steer which syscalls new calls use. Each entry is a name prefix and a
// multiplier applied to the built-in weight of every syscall whose name starts
// with it; the longest matching prefix wins, syscalls matching none keep 1.0,
// and 0 means "never pick". For example, to concentrate on DirectX kernel calls
// and leave DirectComposition alone:
//
//   setSyscallFocus({{"NtGdiDdDDI", 4.0}, {"NtDxgk", 4.0}, {"NtDComposition", 0.0}});
//
// An empty list restores the built-in weights. Only the choice of new calls is
// affected: calls already in corpus entries stay. Returns how many syscalls can
// still be picked; if that would be none, the focus is ignored.
// Applies to every "syscall" mutator in the process; may be called at any time.
std::size_t setSyscallFocus(const std::vector<std::pair<std::string, double>>& prefixes);
