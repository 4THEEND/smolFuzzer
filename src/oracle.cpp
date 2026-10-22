#include "oracle.hpp"

#include <array>
#include <cstring>

namespace
{

    // Hit count -> bucket bit (AFL classification).
    constexpr std::array<uint8_t, 256> kBuckets = []
    {
        std::array<uint8_t, 256> t{};
        for (int c = 0; c < 256; ++c)
        {
            t[c] = c == 0     ? 0
                   : c == 1   ? 1
                   : c == 2   ? 2
                   : c == 3   ? 4
                   : c <= 7   ? 8
                   : c <= 15  ? 16
                   : c <= 31  ? 32
                   : c <= 127 ? 64
                              : 128;
        }
        return t;
    }();

} // namespace

VirginMap_t::Result VirginMap_t::update(std::span<const uint8_t> bitmap)
{
    if (bitmap.empty())
        return Result::NoCoverage;

    // The bitmap size is only known once a NyxProcess exists, hence the lazy init.
    std::call_once(Init_, [&]
                   {
                       Size_ = bitmap.size();
                       Bits_ = std::make_unique<std::atomic<uint8_t>[]>(Size_); // zero-initialized
                   });

    const std::size_t n = std::min(Size_, bitmap.size());
    const uint8_t *bm = bitmap.data();
    bool found = false;
    bool anyHit = false;

    auto check = [&](std::size_t i)
    {
        const uint8_t b = kBuckets[bm[i]];
        if (b == 0)
            return;
        anyHit = true;
        auto &v = Bits_[i];
        if ((v.load(std::memory_order_relaxed) & b) == b)
            return; // fast path: known
        if ((v.fetch_or(b, std::memory_order_relaxed) & b) == 0)
            found = true; // we won the race
    };

    // The map is mostly zeros: skip 8 bytes at a time.
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        uint64_t word;
        std::memcpy(&word, bm + i, sizeof(word));
        if (word == 0)
            continue;
        for (std::size_t j = i; j < i + 8; ++j)
            check(j);
    }
    for (; i < n; ++i)
        check(i);

    if (!anyHit)
        return Result::NoCoverage;
    return found ? Result::NewBits : Result::Known;
}

Verdict CoverageOracle_t::evaluate(const ExecResult_t &res)
{
    using R = VirginMap_t::Result;

    switch (res.ret)
    {
    case Normal:
        return Coverage_.update(res.bitmap) == R::NewBits ? Verdict::Interesting : Verdict::Boring;

    case Crash:
    case Asan:
        // No coverage (no instrumentation, tracing off...): we can't dedup on
        // the bitmap, so keep it; the corpus still dedups crashes by content.
        return CrashCoverage_.update(res.bitmap) == R::Known ? Verdict::Boring : Verdict::Objective;

    default:
        return Verdict::Boring;
    }
}
