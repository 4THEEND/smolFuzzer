#include "agent.hpp"


#include <array>
#include <string_view>


std::string_view ret_name(NyxReturnValue r) {
    switch (r) {
    case Normal:                return "Normal";
    case Crash:                 return "Crash";
    case Asan:                  return "Asan";
    case Timeout:               return "Timeout";
    case InvalidWriteToPayload: return "InvalidWriteToPayload";
    case Error:                 return "Error";
    case IoError:               return "IoError";
    case Abort:                 return "Abort";
    default:                    return "Unknown";
    }
}


Agent_t::Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id)
 : Config_(config), Corpus_(Corpus), Proc_(nyx_new(config.nyxConf, id), &nyx_shutdown), AgentId_(id), Status_(AgentStatus::Init) {
    if (!Proc_) {
        DebugPrint<0>("agent", "[-] nyx_new failed\n");
        setStatus(AgentStatus::Errored);

        return;
    }

    const auto sec  = std::min(config.timeout_ms / 1000, 255UL);
    const auto usec = (config.timeout_ms % 1000) * 1000;
    nyx_option_set_reload_mode(Proc_.get(), true);
    nyx_option_set_timeout(Proc_.get(), static_cast<uint8_t>(sec), static_cast<uint32_t>(usec));
    nyx_option_apply(Proc_.get());

    setStatus(AgentStatus::Ready);
 }


void Agent_t::run(){
    setStatus(AgentStatus::Running);
    bool hadError = false;

    // Dummy input: fixed bytes, the agent can ignore or parse them
    std::array<uint8_t, 4> input{0xde, 0xaa, 0xbe, 0xef};
    std::array<char, 1024> aux{};

    for (unsigned long i = 0; !g_stop && (Config_.runs == 0 || i < Config_.runs); ++i) {
        nyx_set_afl_input(Proc_.get(), input.data(), static_cast<uint32_t>(input.size()));
        const NyxReturnValue r = nyx_exec(Proc_.get());

        uint32_t n = nyx_get_aux_string(Proc_.get(), reinterpret_cast<uint8_t *>(aux.data()),
                                        static_cast<uint32_t>(aux.size() - 1));
        n = std::min<uint32_t>(n, aux.size() - 1);
        const std::string_view aux_str(aux.data(), n);

        DebugPrint<1>("agent", "[{}] {}\n", i, ret_name(r));
        if (!aux_str.empty()) DebugPrint<1>("agent", "Last Msg: {}\n", aux_str);

        if (r == Error || r == IoError || r == Abort) {
            hadError = true;
            break;
        }
    }

    setStatus(hadError ? AgentStatus::Errored : AgentStatus::Stopped);
 }