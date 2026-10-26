import re
import struct

TARGET_DRIVER = None
SIG16_BOARD_SET = bytes.fromhex('48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18')

P_GPU_REGISTRY = [0x48, 0x8B, 0x05, None, None, None, None,
                  0x44, 0x8B, 0xD9,
                  0x4C, 0x8B, 0x88, None, None, None, None]
P_SET_AMOUNT = [0x48, 0x83, 0xEC, 0x38,
               0x48, 0x8B, 0x81, None, None, None, None,
               0x44, 0x8B, 0xC2,
               0x80, 0xB8, None, None, None, None, 0x00]
P_SET_ELIG = [0x48, 0x83, 0xEC, 0x28,
              0x48, 0x8B, 0x81, None, None, None, None,
              0x80, 0xB8, None, None, None, None, 0x00]
P_UPPER_LOAD = [0x44, 0x8B, 0x8B, None, None, None, None]
P_F7_RECORD = [0x66, 0xC7, 0x44, 0x24, 0x48, 0xF7, 0x03]
P_BOARD_SET = [0x48, 0x89, 0x5C, 0x24, 0x08,
               0x48, 0x89, 0x6C, 0x24, 0x10,
               0x48, 0x89, 0x74, 0x24, 0x18]

F7_BACKWARD_WINDOW = 0x180
HYP = {
    "OFF_ROOT_REGISTRY": 0x1CC0,
    "OFF_ROOT_LOOKUP_FN": 0x1CF8,
    "OFF_BOARD_SET_FN": 0x2D0,
    "OFF_SELECTOR2": 0x104,
    "OFF_SELECTOR3": 0x1F4,
    "OFF_TABLE_ENTRY_PTR": 0x48A48,
    "OFF_TABLE_ENTRY_GPUID": 0x48A50,
    "OFF_TABLE_COUNT": 0x48C48,
    "GPU_ENTRY_STRIDE": 0x10,
    "GPU_COUNT_MAX": 32,
}

class AnalysisError(Exception):
    """任何校验失败/歧义，一律抛出并拒绝写出目标头。"""

    def __init__(self, msg, diag=None):
        super(AnalysisError, self).__init__(msg)
        self.diag = diag or {}
SETTER_MAX_DISTANCE = 0x1000
class PeImage(object):
    def __init__(self, data, source_name):
        self.data = data
        self.source_name = source_name
        if len(data) < 0x200 or data[:2] != b"MZ":
            raise AnalysisError("not an MZ image")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
            raise AnalysisError("bad e_lfanew")
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise AnalysisError("bad PE signature")
        (self.machine, self.number_of_sections, self.timestamp) = \
            struct.unpack_from("<HHI", data, e_lfanew + 4)
        size_of_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic != 0x20B:
            raise AnalysisError("expected PE32+ (64-bit) image")
        self.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        if self.machine != 0x8664:
            raise AnalysisError("expected machine amd64, got 0x%04X" % self.machine)
        if self.size_of_image == 0:
            raise AnalysisError("SizeOfImage is zero")

        self.sections = []
        sec_off = opt + size_of_opt
        for i in range(self.number_of_sections):
            entry = data[sec_off + i * 40: sec_off + (i + 1) * 40]
            if len(entry) < 40:
                raise AnalysisError("truncated section table")
            name = entry[0:8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", entry, 8)
            chars = struct.unpack_from("<I", entry, 36)[0]
            self.sections.append({
                "name": name, "virtual_size": vsize, "va": va,
                "raw_size": rawsize, "raw_ptr": rawptr,
                "executable": bool(chars & 0x20000000),
                "characteristics": chars,
            })

    def exec_sections(self):
        return [s for s in self.sections if s["executable"]]

    def rva_to_offset(self, rva):
        for s in self.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["va"] <= rva < s["va"] + span:
                off = rva - s["va"] + s["raw_ptr"]
                if off < s["raw_ptr"] + s["raw_size"]:
                    return off
                return None  # 在虚拟范围内但无原始数据
        return None

    def containing_section(self, rva):
        for s in self.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["va"] <= rva < s["va"] + span:
                return s
        return None

    def read_at_rva(self, rva, size):
        off = self.rva_to_offset(rva)
        if off is None:
            raise AnalysisError("RVA 0x%X has no raw data" % rva)
        return self.data[off:off + size]
def pattern_to_regex(pattern):
    parts = []
    for b in pattern:
        if b is None:
            parts.append(b".")
        else:
            parts.append(re.escape(bytes([b])))
    return re.compile(b"".join(parts), re.DOTALL)

def scan_exec(pe, pattern):
    """返回 [(rva, match_bytes)]，仅扫描可执行节。"""
    rx = pattern_to_regex(pattern)
    hits = []
    for s in pe.exec_sections():
        raw_avail = min(s["raw_size"], len(pe.data) - s["raw_ptr"])
        if raw_avail <= 0:
            continue
        buf = pe.data[s["raw_ptr"]: s["raw_ptr"] + raw_avail]
        for m in rx.finditer(buf):
            hits.append((s["va"] + m.start(), m.group()))
    return hits

def disp32(buf, pos):
    return struct.unpack_from("<i", buf, pos)[0]

def require_unique(hits, what, allow_zero=False):
    if not hits and allow_zero:
        return None
    if len(hits) != 1:
        raise AnalysisError(
            "pattern for %s matched %d site(s) in executable sections; "
            "expected exactly 1 (fail-closed, manual review required)"
            % (what, len(hits)))
    return hits[0]
def analyze(pe, board_set_rva):
    result = {
        "target_driver": TARGET_DRIVER,
        "source": pe.source_name,
        "pe_identity": {
            "machine": "0x%04X" % pe.machine,
            "time_date_stamp": "0x%08X" % pe.timestamp,
            "size_of_image": "0x%08X" % pe.size_of_image,
        },
        "derived": {},
        "hypothesis": dict(HYP),
        "checks": [],
        "board_set": None,
    }
    derived = result["derived"]

    def check(ok, msg):
        result["checks"].append({"ok": bool(ok), "message": msg})
        if not ok:
            raise AnalysisError(msg)
    hits = scan_exec(pe, P_GPU_REGISTRY)
    rva, mbytes = require_unique(hits, "GPU registry entry (P1)")
    d_global = disp32(mbytes, 3)
    rva_gpu_global = rva + 7 + d_global
    off_gpu_table = disp32(mbytes, 13) & 0xFFFFFFFF
    derived["RVA_GPU_REGISTRY_FN"] = rva
    derived["RVA_GPU_GLOBAL"] = rva_gpu_global
    derived["OFF_GLOBAL_GPU_TABLE"] = off_gpu_table
    derived["_sig_gpu_registry"] = mbytes.hex()
    sec = pe.containing_section(rva_gpu_global)
    check(sec is not None and not sec["executable"],
          "P1: RVA_GPU_GLOBAL 0x%X must fall inside a non-executable section" % rva_gpu_global)
    check(0 < off_gpu_table < 0x10000,
          "P1: OFF_GLOBAL_GPU_TABLE 0x%X out of plausible range" % off_gpu_table)
    hits = scan_exec(pe, P_SET_AMOUNT)
    cands2 = []
    for rva2, m2 in hits:
        d_major = disp32(m2, 7) & 0xFFFFFFFF
        d_init = disp32(m2, 16) & 0xFFFFFFFF
        if 0x100 <= d_major < 0x10000 and d_init > 0x100:
            cands2.append((rva2, m2, d_major, d_init))
    if len(cands2) != 1:
        raise AnalysisError(
            "pattern for SetAmount (P2) matched %d plausible site(s); expected exactly 1"
            % len(cands2),
            diag={"P2_candidates": [
                {"rva": "0x%08X" % r, "off_major_power_root": "0x%X" % dm,
                 "off_root_init": "0x%X" % di}
                for r, _, dm, di in cands2]})
    rva2, m2, off_major_root, off_root_init = cands2[0]
    derived["RVA_SET_AMOUNT"] = rva2
    derived["OFF_MAJOR_POWER_ROOT"] = off_major_root
    derived["OFF_ROOT_INIT"] = off_root_init
    derived["_sig_set_amount"] = m2.hex()
    hits = scan_exec(pe, P_SET_ELIG)
    cands3 = []
    for rva3, m3 in hits:
        d_major = disp32(m3, 7) & 0xFFFFFFFF
        d_init = disp32(m3, 13) & 0xFFFFFFFF
        if d_major == off_major_root and d_init == off_root_init:
            cands3.append((rva3, m3, d_major, d_init))
    if len(cands3) > 1:
        near = [c for c in cands3 if abs(c[0] - rva2) <= SETTER_MAX_DISTANCE]
        if len(near) == 1:
            cands3 = near
    if len(cands3) != 1:
        raise AnalysisError(
            "pattern for SetEligibility (P3) matched %d cross-consistent site(s); "
            "expected exactly 1 (fail-closed, manual review required)" % len(cands3),
            diag={"P3_candidates": [
                {"rva": "0x%08X" % r, "distance_to_set_amount": r - rva2,
                 "off_major_power_root": "0x%X" % dm, "off_root_init": "0x%X" % di}
                for r, _, dm, di in cands3]})
    rva3, m3, _, _ = cands3[0]
    derived["RVA_SET_ELIG"] = rva3
    derived["_sig_set_elig"] = m3.hex()
    rec_hits = scan_exec(pe, P_F7_RECORD)
    upper_rx = pattern_to_regex(P_UPPER_LOAD)
    candidates = []
    for rva_rec, rec_bytes in rec_hits:
        off = pe.rva_to_offset(rva_rec)
        if off is None:
            continue
        win_start = max(0, off - F7_BACKWARD_WINDOW)
        window = pe.data[win_start:off]
        loads = []
        for m in upper_rx.finditer(window):
            rva_up = rva_rec - (off - (win_start + m.start()))
            loads.append((rva_up, m.group(), disp32(m.group(), 3) & 0xFFFFFFFF))
        candidates.append((rva_rec, rec_bytes, loads))
    if not candidates:
        raise AnalysisError("P4: no F7 record found in executable sections")
    if len(candidates) > 1:
        raise AnalysisError(
            "P4: %d F7-record candidates; ambiguous, manual review required"
            % len(candidates),
            diag={"P4_candidates": [
                {"rva_f7_record": "0x%08X" % rc,
                 "loads": [{"rva": "0x%08X" % ru, "disp": "0x%X" % d} for ru, _, d in ls]}
                for rc, _, ls in candidates]})
    rva_rec, rec_bytes, loads = candidates[0]
    expected_upper = off_root_init + 0x14
    matching = [l for l in loads if l[2] == expected_upper]
    if len(matching) != 1:
        raise AnalysisError(
            "P4: expected exactly one upper-load with disp 0x%X (INIT+0x14) before "
            "the F7 record; found %d. Loads seen: %s. Root field family may have "
            "drifted — manual RE required (refusing to generate)"
            % (expected_upper, len(matching),
               ", ".join("0x%X@0x%X" % (d, ru) for ru, _, d in loads) or "none"),
            diag={"P4_record_rva": "0x%08X" % rva_rec,
                  "loads": [{"rva": "0x%08X" % ru, "disp": "0x%X" % d}
                            for ru, _, d in loads]})
    rva_up, up_bytes, off_root_upper = matching[0]
    derived["RVA_F7_RECORD"] = rva_rec
    derived["RVA_F7_UPPER_LOAD"] = rva_up
    derived["OFF_ROOT_UPPER"] = off_root_upper
    derived["_sig_f7_record"] = rec_bytes.hex()
    derived["_sig_upper_load"] = up_bytes.hex()
    check(rva_up < rva_rec, "P4: upper load must precede the F7 record")
    check(off_root_upper > off_root_init,
          "P4: OFF_ROOT_UPPER 0x%X not above OFF_ROOT_INIT 0x%X"
          % (off_root_upper, off_root_init))
    check(off_root_upper == off_root_init + 0x14,
          "root field family verified: OFF_ROOT_UPPER=0x%X == OFF_ROOT_INIT+0x14=0x%X"
          % (off_root_upper, off_root_init + 0x14))
    derived["OFF_ROOT_ELIG"] = off_root_init + 1
    derived["OFF_ROOT_AMOUNT_ACTIVE"] = off_root_init + 2
    derived["OFF_ROOT_AMOUNT"] = off_root_init + 8
    derived["OFF_ROOT_POLICY_KEY"] = off_root_init + 0xC
    derived["OFF_ROOT_LOWER"] = off_root_init + 0x10
    if board_set_rva is not None:
        try:
            got = pe.read_at_rva(board_set_rva, len(SIG16_BOARD_SET))
        except AnalysisError:
            raise AnalysisError(
                "P5: --board-set-rva 0x%X is not readable inside the image"
                % board_set_rva)
        check(bytes(got) == SIG16_BOARD_SET,
              "P5: bytes at --board-set-rva 0x%X do not match the type-0 board "
              "setter prologue" % board_set_rva)
        result["board_set"] = {
            "RVA_BOARD_TYPE0_SET": board_set_rva,
            "signature": SIG16_BOARD_SET.hex(),
        }
    return result
