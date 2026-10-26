#include <Windows.h>
#include <cstdio>
#include <cwchar>
#include "..\\shared\\nvpwr_ioctl.h"

static const char* StateName(ULONG s)
{
    switch (s) {
    case NvpwrStateArmed: return "ARMED";
    case NvpwrStateApplied: return "APPLIED";
    case NvpwrStateMixed: return "MIXED";
    case NvpwrStateWrongBuild: return "WRONG_BUILD";
    case NvpwrStateModuleNotFound: return "MODULE_NOT_FOUND";
    case NvpwrStateGpuNotFound: return "GPU_NOT_FOUND";
    case NvpwrStateContextInvalid: return "CONTEXT_INVALID";
    case NvpwrStatePreconditionNotReady: return "PRECONDITION_NOT_READY";
    case NvpwrStateStockBaseline: return "STOCK_BASELINE";
    default: return "UNKNOWN";
    }
}

static ULONG ParseProfile(const wchar_t* s)
{
    if (!s) return NvpwrProfileUnknown;
    
    if (_wcsicmp(s, L"all") == 0 ||
        _wcsicmp(s, L"auto") == 0 ||
        _wcsicmp(s, L"generic") == 0 ||
        _wcsicmp(s, L"unlimited") == 0) {
        return NvpwrProfileUnlimited;
    }
    const wchar_t* p = s;
    if (_wcsicmp(s, L"30xx") == 0 ||
        _wcsicmp(s, L"40xx") == 0 ||
        _wcsicmp(s, L"50xx") == 0) {
        return NvpwrProfileUnlimited;
    }
    if ((p[0] == L'3' || p[0] == L'4' || p[0] == L'5') &&
        (p[1] >= L'0' && p[1] <= L'9') &&
        (p[2] >= L'0' && p[2] <= L'9')) {
        wchar_t suffix = p[3];
        if (suffix == L'\0' || (suffix == L't' || suffix == L'T') &&
            (p[4] == L'i' || p[4] == L'I') && p[5] == L'\0') {
            return NvpwrProfileUnlimited;
        }
    }
    return NvpwrProfileUnknown;
}

static bool ParseWatts(const wchar_t* text, ULONG* milliwatts)
{
    if (!text || !*text || !milliwatts) return false;
    wchar_t* end = nullptr;
    unsigned long long watts = _wcstoui64(text, &end, 10);
    if (end == text || *end != L'\0' || watts > (0xFFFFFFFFull / 1000ull)) return false;
    *milliwatts = (ULONG)(watts * 1000ull);
    return true;
}

static void PrintUsage()
{
    std::printf(
        "Usage: NvpwrCtl status | set <all|auto|generic|unlimited|"
        "<30xx|40xx|50xx model>> <watts> | restore\n"
        "Models: 30xx/40xx/50xx and optional Ti suffix.");
}

static void PrintPower(const char* label, ULONG v)
{
    if (v == 0xFFFFFFFFu) std::printf("%-24s : FFFFFFFF\n", label);
    else std::printf("%-24s : %lu (%.3f W)\n", label, v, v / 1000.0);
}

static bool ShowStatus(HANDLE h)
{
    NVPWR_STATUS s{};
    DWORD got = 0;
    if (!DeviceIoControl(h, IOCTL_NVPWR_STATUS, nullptr, 0, &s, sizeof(s), &got, nullptr) || got < sizeof(s)) {
        std::printf("STATUS failed: Win32=%lu bytes=%lu\n", GetLastError(), got);
        return false;
    }

    std::printf("State                : %s (%lu)\n", StateName(s.State), s.State);
    std::printf("Detail               : %lu\n", s.Detail);
    std::printf("Last NTSTATUS        : 0x%08lX\n", (unsigned long)s.LastNtStatus);
    std::printf("Last NVIDIA status   : 0x%08lX\n", s.LastNvStatus);
    std::printf("TimeDateStamp        : 0x%08lX\n", s.TimeDateStamp);
    std::printf("SizeOfImage          : 0x%08lX\n", s.SizeOfImage);
    std::printf("ModuleBase           : 0x%016llX\n", (unsigned long long)s.ModuleBase);
    std::printf("Flags init/elig/amt  : %u / %u / %u\n", s.RootInitialized, s.Eligibility, s.AmountActive);
    std::printf("Active profile       : %lu\n", s.ActiveProfile);
    PrintPower("OEM baseline", s.OemBaseline);
    PrintPower("F7 input (cTGP)", s.CtgpTarget);
    PrintPower("amount (dynamic)", s.PpabAmount);
    PrintPower("UPPER (saturation)", s.UpperBoundary);
    PrintPower("predicted F7", s.PredictedF7);
    PrintPower("MAX effective", s.MaxEffective);
    PrintPower("Current effective", s.CurrentEffective);
    PrintPower("Current F7", s.CurrentF7Value);
    PrintPower("Applied target", s.AppliedTarget);

    if (s.BoardSetFunction) {
        unsigned long long rva = s.BoardSetFunction - s.ModuleBase;
        std::printf("BoardSetFunction     : 0x%016llX (RVA 0x%llX)\n",
            (unsigned long long)s.BoardSetFunction, rva);
        if (rva == 0 || rva >= s.SizeOfImage)
            std::printf("  !! Board setter RVA out of image range\n");
        else if (!s.SupportedMin && s.State != NvpwrStateStockBaseline && s.State != NvpwrStateMixed)
            std::printf("  (record this RVA for target configuration --board-set-rva 0x%llX)\n", rva);
    }
    return true;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2 || argc > 4) {
        PrintUsage();
        return 2;
    }

    HANDLE h = CreateFileW(NVPWR_DEVICE_WIN32, GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::printf("Cannot open \\\\.\\Nvpwr: Win32=%lu\n", GetLastError());
        return 3;
    }

    int rc = 0;
    if (_wcsicmp(argv[1], L"status") == 0 && argc == 2) {
        rc = ShowStatus(h) ? 0 : 4;
    } else if (_wcsicmp(argv[1], L"restore") == 0 && argc == 2) {
        DWORD got = 0;
        if (!DeviceIoControl(h, IOCTL_NVPWR_RESTORE, nullptr, 0, nullptr, 0, &got, nullptr)) {
            std::printf("Restore failed: Win32=%lu\n", GetLastError());
            rc = 5;
        }
        ShowStatus(h);
    } else if (_wcsicmp(argv[1], L"set") == 0 && argc == 4) {
        ULONG profile = ParseProfile(argv[2]);
        ULONG targetMilliwatts = 0;
        bool valid = profile != NvpwrProfileUnknown &&
            ParseWatts(argv[3], &targetMilliwatts);
        if (!valid) {
            std::printf(
                "Invalid input. Use a 30xx/40xx/50xx model alias or all/generic/unlimited; "
                "watts must fit the 32-bit milliwatt protocol field.\n");
            CloseHandle(h);
            return 2;
        }
        NVPWR_SET_POWER req{};
        req.Version = NVPWR_SET_VERSION;
        req.TargetMilliwatts = targetMilliwatts;
        req.Profile = profile;
        DWORD got = 0;
        if (!DeviceIoControl(h, IOCTL_NVPWR_SET_POWER, &req, sizeof(req), nullptr, 0, &got, nullptr)) {
            std::printf("Set failed: Win32=%lu\n", GetLastError());
            rc = 6;
        }
        ShowStatus(h);
    } else {
        PrintUsage();
        rc = 2;
    }

    CloseHandle(h);
    return rc;
}
