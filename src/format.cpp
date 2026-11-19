#include "format.hpp"

#include <algorithm>

namespace
{

    std::vector<std::unique_ptr<InputFormat_t>> &registry()
    {
        static std::vector<std::unique_ptr<InputFormat_t>> formats;
        return formats;
    }

    class RawFormat_t final : public InputFormat_t
    {
    public:
        bool matches(std::span<const uint8_t>) const override { return true; }

        std::string describe(std::span<const uint8_t> data) const override
        {
            return fmt::format("raw input, {} bytes: {}\n", data.size(), hexPreview(data, 256));
        }

        Input_t minimize(Input_t data, const MinimizeTest_t &test) const override
        {
            return minimizeBytes(std::move(data), test);
        }
    };

} // namespace

bool registerFormat(std::unique_ptr<InputFormat_t> format)
{
    registry().push_back(std::move(format));
    return true;
}

const InputFormat_t &formatFor(std::span<const uint8_t> data)
{
    static const RawFormat_t raw;
    for (const auto &f : registry())
    {
        if (f->matches(data))
            return *f;
    }
    return raw;
}

void zeroUnneeded(std::vector<uint8_t> &data, std::size_t lo, std::size_t hi,
                  const std::function<bool(const std::vector<uint8_t> &)> &accept)
{
    hi = std::min(hi, data.size());
    if (lo >= hi || std::all_of(data.begin() + lo, data.begin() + hi, [](uint8_t b) { return b == 0; }))
        return;

    // Try the whole range; if the bug needs something in it, look in each half.
    // Costs about log2(n) executions per byte that really matters.
    std::vector<uint8_t> cand = data;
    std::fill(cand.begin() + lo, cand.begin() + hi, 0);
    if (accept(cand))
    {
        data = std::move(cand);
        return;
    }
    if (hi - lo == 1)
        return;
    const std::size_t mid = lo + (hi - lo) / 2;
    zeroUnneeded(data, lo, mid, accept);
    zeroUnneeded(data, mid, hi, accept);
}

Input_t minimizeBytes(Input_t data, const MinimizeTest_t &test)
{
    // Delete blocks, large ones first (ddmin without the complement step).
    // The agent never sends an empty payload, so one byte is the floor.
    for (std::size_t chunk = std::max<std::size_t>(data.size() / 2, 1); chunk != 0 && data.size() > 1; chunk /= 2)
    {
        for (std::size_t pos = 0; pos < data.size() && data.size() > 1;)
        {
            const std::size_t len = std::min({chunk, data.size() - pos, data.size() - 1});
            Input_t cand;
            cand.reserve(data.size() - len);
            cand.insert(cand.end(), data.begin(), data.begin() + pos);
            cand.insert(cand.end(), data.begin() + pos + len, data.end());
            if (test(cand))
                data = std::move(cand); // same pos now holds the next block
            else
                pos += chunk;
        }
    }

    zeroUnneeded(data, 0, data.size(), [&](const std::vector<uint8_t> &cand) { return test(cand); });
    return data;
}

std::string hexPreview(std::span<const uint8_t> data, std::size_t limit)
{
    const std::size_t n = std::min(data.size(), limit);
    std::string out, text;
    for (std::size_t i = 0; i < n; ++i)
    {
        out += fmt::format("{:02x} ", data[i]);
        text += data[i] >= 0x20 && data[i] < 0x7F ? static_cast<char>(data[i]) : '.';
    }
    if (n < data.size())
        out += fmt::format("... (+{} bytes) ", data.size() - n);
    if (n != 0)
        out += " |" + text + "|";
    return out;
}
