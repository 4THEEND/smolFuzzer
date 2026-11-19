#pragma once

#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "utils.hpp"

// Asks the VM whether a candidate still triggers the bug being minimized.
// Returns false as well once minimization must end (Ctrl-C, exec budget, VM
// error), so a reducer needs no stop logic of its own: it just runs out of
// candidates that work.
using MinimizeTest_t = std::function<bool(std::span<const uint8_t>)>;

// What the reproducer and the minimizer need to know about a kind of input.
// The format of a testcase is recognised from its bytes (formatFor), so both
// tools work on any file from crashes/ without being told what produced it.
class InputFormat_t
{
public:
    virtual ~InputFormat_t() = default;

    virtual bool matches(std::span<const uint8_t> data) const = 0;

    // Human-readable listing, for bug reports.
    virtual std::string describe(std::span<const uint8_t> data) const = 0;

    // Smallest/simplest variant of `data` found for which `test` is true.
    // `test(data)` is known to be true on entry; the result is `data` itself
    // or a candidate `test` accepted.
    virtual Input_t minimize(Input_t data, const MinimizeTest_t &test) const = 0;
};

// The format of `data`: a registered one if it matches, raw bytes otherwise.
const InputFormat_t &formatFor(std::span<const uint8_t> data);

bool registerFormat(std::unique_ptr<InputFormat_t> format);

// Format-agnostic reduction: delete blocks, then zero what is left. Formats
// can fall back to it for inputs they cannot parse.
Input_t minimizeBytes(Input_t data, const MinimizeTest_t &test);

// Zero the bytes of data[lo, hi) that the bug does not depend on. `accept`
// is given the whole edited buffer. Shared by the reducers.
void zeroUnneeded(std::vector<uint8_t> &data, std::size_t lo, std::size_t hi,
                  const std::function<bool(const std::vector<uint8_t> &)> &accept);

// "00 01 02 ...  |...|" preview of at most `limit` bytes.
std::string hexPreview(std::span<const uint8_t> data, std::size_t limit = 64);

#define NYXFUZZ_FMT_CONCAT_(a, b) a##b
#define NYXFUZZ_FMT_CONCAT(a, b) NYXFUZZ_FMT_CONCAT_(a, b)

//   class MyFormat_t : public InputFormat_t { ... };
//   REGISTER_FORMAT(MyFormat_t);
#define REGISTER_FORMAT(TYPE)                                                \
    static const bool NYXFUZZ_FMT_CONCAT(kFormatRegistered_, __COUNTER__) = \
        ::registerFormat(std::make_unique<TYPE>())
