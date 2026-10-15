#include "../mutator.hpp"
#include "w32k_decode.hpp"

#include <iostream>

namespace Syscall
{

    class SyscallMutator_t final : public Mutator_t
    {
    public:
        Input_t emptyInput() override { return Input_t{0xde, 0xad, 0xbe, 0xef}; };

        void mutate(Input_t &d, MutatorContext_t &ctx) override
        {
            if (d.empty())
                d.push_back(0);

            auto result = W32k::DecodeBatch(d);
            if (!result.ok)
            {
                DebugPrint<1>("Syscall", "Failed to decode the buffer\n");
                return;
            }

            W32k::Print(result, std::cout);
        }
    };

} // namespace syscalls

REGISTER_MUTATOR(Syscall::SyscallMutator_t, "syscall", "Specialised mutator for syscalls");