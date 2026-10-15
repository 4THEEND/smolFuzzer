#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "utils.hpp"


// What a mutator may use besides the input itself. Owned by one agent.
struct MutatorContext_t {
    Rng_t& rng;                            // the agent's private RNG
    std::size_t maxSize;                   // max payload size accepted by the VM
    std::function<InputPtr()> pickOther;   // another corpus entry (for splicing); may return nullptr
};



class Mutator_t {
public:
    virtual ~Mutator_t() = default;
    virtual void mutate(Input_t& data, MutatorContext_t& ctx) = 0;
};


class MutatorRegistry_t {
public:
    using Factory_t = std::function<std::unique_ptr<Mutator_t>()>;

    static MutatorRegistry_t& instance() {
        static MutatorRegistry_t registry;
        return registry;
    }

    bool add(std::string name, std::string description, Factory_t factory) {
        return Entries_.try_emplace(std::move(name), Entry_t{std::move(description), std::move(factory)}).second;
    }

    std::unique_ptr<Mutator_t> create(std::string_view name) const {
        const auto it = Entries_.find(name);
        return it == Entries_.end() ? nullptr : it->second.factory();
    }

    bool contains(std::string_view name) const { return Entries_.find(name) != Entries_.end(); }

    std::string describe() const {
        std::string out;
        for (const auto& [name, e] : Entries_) out += fmt::format("  {:<10} {}\n", name, e.description);
        return out;
    }

private:
    struct Entry_t {
        std::string description;
        Factory_t factory;
    };
    std::map<std::string, Entry_t, std::less<>> Entries_;
};


#define NYXFUZZ_CONCAT_(a, b) a##b
#define NYXFUZZ_CONCAT(a, b) NYXFUZZ_CONCAT_(a, b)

//   class MyMutator_t : public Mutator_t { ... };
//   REGISTER_MUTATOR(MyMutator_t, "mine", "my custom strategy");
#define REGISTER_MUTATOR(TYPE, NAME, DESC)                                           \
    static const bool NYXFUZZ_CONCAT(kMutatorRegistered_, __COUNTER__) =            \
        ::MutatorRegistry_t::instance().add(NAME, DESC, []() -> std::unique_ptr<Mutator_t> { \
            return std::make_unique<TYPE>();                                         \
        })
