"""检查目标映像并生成构建头文件。"""

import argparse
import json
from pathlib import Path
import struct
import sys
import signatures
import discover
import anchors

class Rejected(ValueError):
    pass


class StageFailure(Rejected):
    def __init__(self, stage, error):
        super().__init__("{}：{}".format(stage, error))
        self.original = error
        self.diag = {
            "stage": stage, "exception": type(error).__name__, "message": str(error),
            "details": getattr(error, "diag", {}),
        }


def run_stage(name, operation, *arguments):
    try:
        return operation(*arguments)
    except StageFailure:
        raise
    except Exception as error:
        raise StageFailure(name, error) from error


def write_diagnostics(path, result):
    if not path:
        return
    try:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError) as error:
        print("诊断文件未能写入 {}：{}".format(path, error), file=sys.stderr)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def validate_pe(data):
    """补足上游解析器缺少的边界检查，拒绝截断、重叠或非内核 PE。"""
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise Rejected("不是完整的 MZ 映像")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe < 0x40 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise Rejected("PE 文件头越界或签名错误")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    sections = optional + optional_size
    if machine != 0x8664 or not 1 <= count <= 96:
        raise Rejected("仅接受 AMD64 映像，且节区数量必须合理")
    if optional_size < 0xF0 or sections + count * 40 > len(data):
        raise Rejected("可选文件头或节区表被截断")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise Rejected("仅接受 PE32+ 映像")
    image_size, header_size = struct.unpack_from("<II", data, optional + 56)
    if not image_size or not sections + count * 40 <= header_size <= len(data):
        raise Rejected("映像大小或文件头大小无效")
    if struct.unpack_from("<H", data, optional + 68)[0] != 1:
        raise Rejected("不是 Native 子系统映像")
    raw_ranges, virtual_ranges = [], []
    for index in range(count):
        entry = sections + index * 40
        size, va, raw_size, raw = struct.unpack_from("<IIII", data, entry + 8)
        span = max(size, raw_size)
        if not span or va < header_size or va + span > image_size:
            raise Rejected("节区虚拟范围无效或越过 SizeOfImage")
        virtual_ranges.append((va, va + span))
        if raw_size:
            if raw < header_size or raw + raw_size > len(data):
                raise Rejected("节区原始数据被截断或覆盖文件头")
            raw_ranges.append((raw, raw + raw_size))
    for ranges in (raw_ranges, virtual_ranges):
        ordered = sorted(ranges)
        if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
            raise Rejected("节区范围重叠，拒绝使用歧义映像")


def validate_derived_ranges(pe, result):
    """上游 F7 向后搜索不能越过当前可执行节区。"""
    derived = result["derived"]
    for key, value in derived.items():
        if key.startswith("RVA_"):
            section = pe.containing_section(value)
            if section is None:
                raise Rejected(key + " 不在映像内")
            if key != "RVA_GPU_GLOBAL" and not section["executable"]:
                raise Rejected(key + " 不在可执行节区内")
    record_section = pe.containing_section(derived["RVA_F7_RECORD"])
    upper_section = pe.containing_section(derived["RVA_F7_UPPER_LOAD"])
    if record_section != upper_section:
        raise Rejected("F7 与 UPPER 加载跨节区，不能接受")
    for name, raw_signature in derived.items():
        if not name.startswith("_sig_"):
            continue
        mapping = {
            "_sig_gpu_registry": "RVA_GPU_REGISTRY_FN",
            "_sig_set_amount": "RVA_SET_AMOUNT",
            "_sig_set_elig": "RVA_SET_ELIG",
            "_sig_f7_record": "RVA_F7_RECORD",
            "_sig_upper_load": "RVA_F7_UPPER_LOAD",
        }
        rva = derived[mapping[name]]
        section = pe.containing_section(rva)
        length = len(bytes.fromhex(raw_signature))
        if rva - section["va"] + length > section["raw_size"]:
            raise Rejected("代码签名跨越节区原始数据边界")
    if result.get("board_set"):
        board = result["board_set"]
        rva = board["RVA_BOARD_TYPE0_SET"]
        section = pe.containing_section(rva)
        if section is None or not section["executable"]:
            raise Rejected("Board 地址不在可执行节区")
        if rva - section["va"] + len(bytes.fromhex(board["signature"])) > section["raw_size"]:
            raise Rejected("Board 签名跨越节区原始数据边界")


def render_header(result, target):
    lines = [
        "/* 自动生成；离线配置匹配不代表当前硬件已验证。 */",
        "#pragma once",
        "#define NVPWR_TARGET_DRIVER %du" % target,
        "#define NVPWR_EXPECTED_TIMESTAMP %su"
        % result["pe_identity"]["time_date_stamp"],
        "#define NVPWR_EXPECTED_SIZE %su" % result["pe_identity"]["size_of_image"],
    ]
    values = dict(result["derived"])
    values.update(result["hypothesis"])
    fields = result["source_layout"]
    required = {"SLOT_MODE", "SLOT_COUNT", "SLOT_EFFECTIVE", "SLOT_SOURCE_ID0",
                "SLOT_SOURCE_VALUE0", "SLOT_SOURCE_STRIDE", "SLOT_SOURCE_MAX"}
    if set(fields) != required:
        raise Rejected("缺少完整 selector 源数组布局，不能生成目标头。")
    values.update(fields)
    values["RVA_BOARD_TYPE0_SET"] = result["board_set"]["RVA_BOARD_TYPE0_SET"]
    for name, value in values.items():
        if not name.startswith("_sig_"):
            lines.append("#define %s 0x%Xu" % (name, value))
    signatures = {
        "g_SigGpuRegistry": result["derived"]["_sig_gpu_registry"],
        "g_SigUpperLoad": result["derived"]["_sig_upper_load"],
        "g_SigF7Record": result["derived"]["_sig_f7_record"],
        "g_SigBoardSet": result["board_set"]["signature"],
        "g_SigSetAmount": result["derived"]["_sig_set_amount"],
        "g_SigSetElig": result["derived"]["_sig_set_elig"],
    }
    for name, signature in signatures.items():
        encoded = ", ".join("0x%02X" % b for b in bytes.fromhex(signature))
        lines.append("static const UCHAR %s[] = { %s };" % (name, encoded))
    return "\n".join(lines) + "\n"


def inspect(image, version, target_path=None):
    parts = version.split(".")
    if len(parts) != 4 or any(not p.isascii() or not p.isdigit() or int(p) > 65535 for p in parts):
        raise Rejected("无法读取四段文件版本；请检查输入是否为 NVIDIA 驱动原文件。")
    data = run_stage("读取驱动映像", Path(image).read_bytes)
    run_stage("PE 结构检查", validate_pe, data)
    pe = run_stage("PE 节区解析", signatures.PeImage, data, Path(image).name)
    try:
        result = run_stage("快速锚点识别", signatures.analyze, pe, None)
        discovery = run_stage("快速路径对象关联", discover.discover, pe, result)
    except StageFailure as fast_error:
        if not isinstance(fast_error.original, (signatures.AnalysisError, discover.DiscoveryError)):
            raise
        try:
            result = run_stage("后备参数与字段识别", anchors.seed, pe)
            result["anchor_fallback"] = fast_error.diag
            discovery = run_stage("后备路径对象关联", discover.discover, pe, result)
        except StageFailure as fallback_error:
            fallback_error.diag["fast_path_failure"] = fast_error.diag
            raise
    result["hypothesis"] = discovery["layout"]
    result["board_set"] = discovery["board_set"]
    result["source_layout"] = discovery["source_layout"]
    result["discovery"] = discovery
    run_stage("派生地址与签名字节范围检查", validate_derived_ranges, pe, result)
    if target_path:
        target = read_json(target_path)
        if version != target["file_version"]:
            raise Rejected("显式指定的交叉核对配置版本不一致。省略 -TargetPath 可使用自动发现。")
        for key in ("derived", "pe_identity"):
            if result[key] != target[key]:
                raise Rejected("自动发现结果与交叉核对配置不一致：" + key)
        if (discovery["layout"] != target["layout"] or
                discovery["board_set"]["RVA_BOARD_TYPE0_SET"] != target["board_set_rva"]):
            raise Rejected("自动发现的布局或 Board 地址与交叉核对配置不一致。")
    target_number = int(parts[2]) % 10 * 10000 + int(parts[3])
    result["target_driver"] = target_number
    result["file_version"] = version
    return result, target_number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--version", default="")
    parser.add_argument("--target", help="可选：与人工配置交叉核对，不用于自动定位")
    parser.add_argument("--diagnostics", help="可选：保存自动发现证据和未验证项")
    parser.add_argument("--header")
    args = parser.parse_args()
    try:
        result, target_number = inspect(args.image, args.version, args.target)
        if args.header:
            header_text = run_stage("生成目标头内容", render_header, result, target_number)
            path = Path(args.header)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(header_text)
        write_diagnostics(args.diagnostics, result)
        print("自动发现通过：版本 {}，Board RVA=0x{:X}。".format(
            args.version or "未知",
            result["board_set"]["RVA_BOARD_TYPE0_SET"],
        ))
        return 0
    except (OSError, ValueError, KeyError, TypeError, struct.error, signatures.AnalysisError) as error:
        write_diagnostics(args.diagnostics, {
            "status": "DISCOVERY_FAILED", "file_version": args.version,
            "input": str(Path(args.image).absolute()),
            "error": str(error), "diagnostics": getattr(error, "diag", {}),
        })
        print("目标检查失败：" + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
