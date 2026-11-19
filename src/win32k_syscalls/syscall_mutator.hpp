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

#include <shared_mutex>

namespace sysmon {
class ArgPool;
}

// `pool` (and `guard`, if given) must outlive all mutators. Pass nullptr to
// detach. Applies to every "syscall" mutator in the process.
void setSyscallArgPool(const sysmon::ArgPool* pool, std::shared_mutex* guard = nullptr);
