#include "mutator.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>


namespace {

constexpr std::size_t kMaxBlock = 64;

constexpr std::array<int8_t, 9> kInteresting8{-128, -1, 0, 1, 16, 32, 64, 100, 127};
constexpr std::array<int16_t, 10> kInteresting16{-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767};
constexpr std::array<int32_t, 8> kInteresting32{INT32_MIN, -100663046, -32769, 32768,
                                                65535, 65536, 100663045, INT32_MAX};

void writeInt(Input_t& d, std::size_t pos, uint64_t v, std::size_t width, bool bigEndian) {
    for (std::size_t k = 0; k < width; ++k) {
        const std::size_t shift = (bigEndian ? width - 1 - k : k) * 8;
        d[pos + k] = static_cast<uint8_t>(v >> shift);
    }
}


// Flip 1 to 8 random bits.
class BitFlipMutator_t final : public Mutator_t {
public:
    void mutate(Input_t& d, MutatorContext_t& ctx) override {
        if (d.empty()) d.push_back(0);
        const std::size_t flips = 1 + randBelow(ctx.rng, 8);
        for (std::size_t i = 0; i < flips; ++i) {
            const std::size_t bit = randBelow(ctx.rng, d.size() * 8);
            d[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
        }
    }
};


// AFL-like havoc: a random stack of 2..32 small mutations.
class HavocMutator_t final : public Mutator_t {
public:
    void mutate(Input_t& d, MutatorContext_t& ctx) override {
        if (d.empty()) d.push_back(0);
        const unsigned rounds = 1u << (1 + randBelow(ctx.rng, 5));
        for (unsigned r = 0; r < rounds; ++r) mutateOnce(d, ctx);
    }

private:
    static void mutateOnce(Input_t& d, MutatorContext_t& ctx) {
        auto& rng = ctx.rng;
        const std::size_t size = d.size();

        switch (randBelow(rng, 10)) {
        case 0:  // bit flip
            d[randBelow(rng, size)] ^= static_cast<uint8_t>(1u << randBelow(rng, 8));
            break;
        case 1:  // random byte
            d[randBelow(rng, size)] = static_cast<uint8_t>(rng());
            break;
        case 2:  // interesting 8
            d[randBelow(rng, size)] = static_cast<uint8_t>(kInteresting8[randBelow(rng, kInteresting8.size())]);
            break;
        case 3:  // interesting 16
            if (size < 2) break;
            writeInt(d, randBelow(rng, size - 1),
                     static_cast<uint16_t>(kInteresting16[randBelow(rng, kInteresting16.size())]), 2, coinFlip(rng));
            break;
        case 4:  // interesting 32
            if (size < 4) break;
            writeInt(d, randBelow(rng, size - 3),
                     static_cast<uint32_t>(kInteresting32[randBelow(rng, kInteresting32.size())]), 4, coinFlip(rng));
            break;
        case 5: {  // small arithmetic
            const std::size_t pos = randBelow(rng, size);
            const auto delta = static_cast<uint8_t>(1 + randBelow(rng, 35));
            d[pos] = static_cast<uint8_t>(coinFlip(rng) ? d[pos] + delta : d[pos] - delta);
            break;
        }
        case 6: {  // delete a block
            if (size < 2) break;
            const std::size_t len = 1 + randBelow(rng, std::min(size - 1, kMaxBlock));
            const std::size_t pos = randBelow(rng, size - len + 1);
            d.erase(d.begin() + pos, d.begin() + pos + len);
            break;
        }
        case 7: {  // insert a block (cloned from the input or constant random byte)
            if (size >= ctx.maxSize) break;
            const std::size_t len = 1 + randBelow(rng, std::min(ctx.maxSize - size, kMaxBlock));
            const std::size_t pos = randBelow(rng, size + 1);
            if (coinFlip(rng) && len <= size) {
                const std::size_t src = randBelow(rng, size - len + 1);
                const Input_t block(d.begin() + src, d.begin() + src + len);  // copy: inserting a range of itself is UB
                d.insert(d.begin() + pos, block.begin(), block.end());
            } else {
                d.insert(d.begin() + pos, len, static_cast<uint8_t>(rng()));
            }
            break;
        }
        case 8: {  // overwrite with a chunk of itself
            if (size < 2) break;
            const std::size_t len = 1 + randBelow(rng, std::min(size - 1, kMaxBlock));
            const std::size_t src = randBelow(rng, size - len + 1);
            const std::size_t dst = randBelow(rng, size - len + 1);
            std::memmove(d.data() + dst, d.data() + src, len);
            break;
        }
        case 9: {  // memset a block
            const std::size_t len = 1 + randBelow(rng, std::min(size, kMaxBlock));
            const std::size_t pos = randBelow(rng, size - len + 1);
            std::fill_n(d.begin() + pos, len, static_cast<uint8_t>(rng()));
            break;
        }
        }
    }
};


// Splice with another corpus entry, then havoc.
class SpliceMutator_t final : public Mutator_t {
public:
    void mutate(Input_t& d, MutatorContext_t& ctx) override {
        const InputPtr other = ctx.pickOther ? ctx.pickOther() : nullptr;
        if (other && !other->empty() && d.size() >= 2) {
            const std::size_t cutA = 1 + randBelow(ctx.rng, d.size() - 1);
            const std::size_t cutB = randBelow(ctx.rng, other->size());
            d.resize(cutA);
            d.insert(d.end(), other->begin() + static_cast<std::ptrdiff_t>(cutB), other->end());
            if (d.size() > ctx.maxSize) d.resize(ctx.maxSize);
        }
        Havoc_.mutate(d, ctx);
    }

private:
    HavocMutator_t Havoc_;
};

}  // namespace


REGISTER_MUTATOR(BitFlipMutator_t, "bitflip", "flip 1-8 random bits");
REGISTER_MUTATOR(HavocMutator_t,   "havoc",   "AFL-like stacked random mutations (default)");
REGISTER_MUTATOR(SpliceMutator_t,  "splice",  "splice with another corpus entry, then havoc");
