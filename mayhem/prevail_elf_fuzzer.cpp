// libFuzzer harness for the PREVAIL eBPF verifier vendored at external/ebpf-verifier:
// ELF/BTF loading, unmarshalling, CFG construction and abstract interpretation.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <variant>
#include <vector>

#include "ebpf_verifier.hpp"
#include "io/elf_loader.hpp"

using namespace prevail;

namespace {
constexpr size_t kMaxProgramsPerInput = 4;

class TempFile {
  public:
    TempFile(const uint8_t* data, size_t size) {
        const char* dir = getenv("TMPDIR");
        std::string tmpl = std::string(dir && *dir ? dir : "/tmp") + "/prevail_fuzz_XXXXXX";
        const int fd = mkstemp(tmpl.data());
        if (fd < 0) {
            abort();
        }
        path_ = tmpl;
        size_t off = 0;
        while (off < size) {
            const ssize_t n = write(fd, data + off, size - off);
            if (n <= 0) {
                abort();
            }
            off += static_cast<size_t>(n);
        }
        close(fd);
    }
    ~TempFile() { unlink(path_.c_str()); }
    const std::string& path() const { return path_; }

  private:
    std::string path_;
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ThreadLocalGuard thread_local_state_guard;
    CrabEnableWarningMsg(false);

    TempFile file(data, size);

    VerifierOptions options;
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups = bpf_conformance_groups_t::default_groups;

    try {
        ElfObject elf{file.path(), options, &platform};
        const auto& programs = elf.get_programs();
        size_t verified = 0;
        for (const RawProgram& raw_prog : programs) {
            if (verified++ >= kMaxProgramsPerInput) {
                break;
            }
            auto prog_or_error = unmarshal(raw_prog, options);
            if (std::holds_alternative<std::string>(prog_or_error)) {
                continue;
            }
            Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), raw_prog.info, options);
            const AnalysisContext context{std::move(prog), options};
            (void)analyze(context);
        }
    } catch (const InternalError&) {
        // PREVAIL documents InternalError as "a bug in Prevail": surface it as a crash.
        throw;
    } catch (const std::exception&) {
        return -1;
    }
    return 0;
}
