"""从指令及调用关系发现目标布局；不使用版本白名单或旧 RVA。"""

from bisect import bisect_right
from pathlib import Path
import re
import struct

import signatures


class DiscoveryError(ValueError):
    def __init__(self, message, diag=None):
        super().__init__(message)
        self.diag = diag or {}


def one(values, what):
    values = list(values)
    if len(values) != 1:
        raise DiscoveryError("{}：需要唯一结果，实际 {} 个：{}".format(what, len(values), values[:16]))
    return values[0]


class Image:
    def __init__(self, pe):
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            from capstone import x86_const
        except ImportError as error:
            raise DiscoveryError("需要反汇编依赖 capstone；请通过 build.ps1 自动准备。") from error
        self.pe = pe
        self.x = x86_const
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.cache = {}
        e = struct.unpack_from("<I", pe.data, 0x3C)[0]
        optional = e + 24
        preferred_base = struct.unpack_from("<Q", pe.data, optional + 24)[0]
        config_rva, config_size = struct.unpack_from("<II", pe.data, optional + 112 + 10 * 8)
        self.guard_dispatch_slot = None
        if config_rva and config_size >= 128:
            config = self.read(config_rva, 128)
            if struct.unpack_from("<I", config)[0] >= 128:
                dispatch_va = struct.unpack_from("<Q", config, 120)[0]
                if dispatch_va >= preferred_base:
                    dispatch_rva = dispatch_va - preferred_base
                    section = pe.containing_section(dispatch_rva)
                    if section and not section["executable"]:
                        self.read(dispatch_rva, 8)
                        self.guard_dispatch_slot = dispatch_rva
        directory = e + 24 + 112 + 3 * 8
        rva, size = struct.unpack_from("<II", pe.data, directory)
        if size == 0 or size % 12:
            raise DiscoveryError("缺少完整 x64 异常目录，不能可靠确定函数边界。")
        self.functions = list(struct.iter_unpack("<III", self.read(rva, size)))
        self.starts = [f[0] for f in self.functions]
        if self.starts != sorted(set(self.starts)):
            raise DiscoveryError("异常目录函数起点未严格递增。")
        for start, end, unwind in self.functions:
            if start >= end or not self.executable(start) or not self.executable(end - 1):
                raise DiscoveryError("异常目录含无效函数范围。")
        self.groups = {}
        self.owners = {}
        for row in self.functions:
            owner = self.unwind_owner(row)
            self.groups.setdefault(owner, []).append(row)
            self.owners[row[0]] = owner
        self.assignments = None

    def unwind_owner(self, row):
        visited = set()
        while True:
            start, end, unwind = row
            if unwind in visited or len(visited) >= 16:
                raise DiscoveryError("异常展开链包含循环或过深。")
            visited.add(unwind)
            head = self.read(unwind, 4)
            if not (head[0] >> 3) & 4:
                return start
            tail = unwind + 4 + ((head[2] + 1) & ~1) * 2
            row = struct.unpack("<III", self.read(tail, 12))
            if row[0] >= row[1] or not self.executable(row[0]):
                raise DiscoveryError("链式异常展开函数无效。")

    def read(self, rva, size):
        section = self.pe.containing_section(rva)
        offset = self.pe.rva_to_offset(rva)
        if (not section or offset is None or size < 0 or
                offset + size > section["raw_ptr"] + section["raw_size"]):
            raise DiscoveryError("读取越过映像原始节：0x{:X}+0x{:X}".format(rva, size))
        return self.pe.data[offset:offset + size]

    def executable(self, rva):
        section = self.pe.containing_section(rva)
        return section is not None and section["executable"]

    def code(self, start, size):
        instructions = list(self.md.disasm(self.read(start, size), start))
        if sum(i.size for i in instructions) != size:
            raise DiscoveryError("函数反汇编未覆盖完整字节范围：0x{:X}".format(start))
        return instructions

    def containing(self, rva):
        index = bisect_right(self.starts, rva) - 1
        if index >= 0:
            start, end, _ = self.functions[index]
            if start <= rva < end:
                return start, end
        raise DiscoveryError("地址不在异常目录函数内：0x{:X}".format(rva))

    def function(self, rva):
        start, end = self.containing(rva)
        owner = self.owners[start]
        if owner not in self.cache:
            ranges = self.groups[owner]
            if sum(b - a for a, b, _ in ranges) > 0x10000:
                raise DiscoveryError("函数体过大，当前规则不处理。")
            # 异常目录可能把 switch 跳转表也包含在函数范围内；
            # 只跟随可达指令，不将表数据线性反汇编成指令。
            pending = [a for a, _, _ in ranges]
            decoded = {}
            while pending:
                address = pending.pop()
                while address not in decoded:
                    interval = next(((a, b) for a, b, _ in ranges if a <= address < b), None)
                    if interval is None:
                        break
                    instruction = next(self.md.disasm(self.read(address, min(15, interval[1] - address)), address), None)
                    if instruction is None:
                        raise DiscoveryError("可达指令无法解码：0x{:X}".format(address))
                    decoded[address] = instruction
                    if instruction.mnemonic.startswith("j"):
                        if instruction.operands[0].type == self.x.X86_OP_IMM:
                            pending.append(instruction.operands[0].imm)
                        if instruction.mnemonic == "jmp":
                            break
                    if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
                        break
                    address += instruction.size
            self.cache[owner] = [decoded[a] for a in sorted(decoded)]
        return self.cache[owner]

    def reg(self, name):
        return getattr(self.x, "X86_REG_" + name.upper())

    def mem(self, op, base=None, size=None):
        return (op.type == self.x.X86_OP_MEM and
                (base is None or op.mem.base == self.reg(base)) and
                (size is None or op.size == size))

    def direct_calls(self, code):
        return [i.operands[0].imm for i in code if i.mnemonic == "call"
                and i.operands[0].type == self.x.X86_OP_IMM]

    def is_guard_dispatch(self, instruction):
        if instruction.mnemonic != "call" or len(instruction.operands) != 1:
            return False
        operand = instruction.operands[0]
        return (
            self.guard_dispatch_slot is not None and self.mem(operand, "rip", 8)
            and instruction.address + instruction.size + operand.mem.disp == self.guard_dispatch_slot
        )

    def resolve_direct_entry(self, destination):
        """仅展开入口处无副作用的直接跳转桩；不猜测间接跳转目标。"""
        visited = set()
        chain = []
        for _ in range(16):
            if destination in visited:
                raise DiscoveryError("直接跳转桩形成循环：0x{:X}".format(destination))
            visited.add(destination)
            if not self.executable(destination):
                raise DiscoveryError("直接调用目标不在执行节内。")
            try:
                start, _ = self.containing(destination)
            except DiscoveryError:
                start = None
            if start is not None and self.owners[start] != destination:
                raise DiscoveryError("直接调用目标落在函数中部或非入口分段。")
            address = destination
            instruction = None
            # 允许有限的 NOP/ENDBR64 入口填充，不能跳过参数或栈改写。
            for _ in range(8):
                section = self.pe.containing_section(address)
                available = section["raw_size"] - (address - section["va"])
                if available <= 0:
                    raise DiscoveryError("跳转桩入口没有原始字节。")
                instruction = next(self.md.disasm(self.read(address, min(15, available)), address), None)
                if instruction is None:
                    raise DiscoveryError("无法解码直接跳转桩入口。")
                if instruction.mnemonic not in ("nop", "endbr64"):
                    break
                address += instruction.size
            else:
                raise DiscoveryError("跳转桩入口填充超过处理上限。")
            if instruction.mnemonic == "jmp":
                ops = instruction.operands
                if len(ops) != 1 or ops[0].type != self.x.X86_OP_IMM:
                    raise DiscoveryError("入口为未处理的间接跳转，不能确定实际函数。")
                target = ops[0].imm
                # 同一函数的入口跳往内部块不是独立跳转桩。
                try:
                    target_start, _ = self.containing(target)
                except DiscoveryError:
                    target_start = None
                if (start is not None and target_start is not None
                        and self.owners[target_start] == destination):
                    return destination, chain
                chain.append({"entry": destination, "jump": address, "destination": target})
                destination = target
                continue
            if start is None:
                raise DiscoveryError("非跳转桩目标缺少函数入口归属。")
            return destination, chain
        raise DiscoveryError("直接跳转桩链超过处理上限。")

    def callee_entries(self, code):
        """识别直接调用和跨 owner 的尾跳转，不把函数内部跳转当调用。"""
        destinations = set()
        for destination in self.direct_calls(code):
            try:
                resolved, _ = self.resolve_direct_entry(destination)
            except DiscoveryError:
                continue
            destinations.add(resolved)
        for instruction in code:
            if (instruction.mnemonic != "jmp" or len(instruction.operands) != 1
                    or instruction.operands[0].type != self.x.X86_OP_IMM):
                continue
            destination = instruction.operands[0].imm
            try:
                source_owner = self.owners[self.containing(instruction.address)[0]]
                resolved, _ = self.resolve_direct_entry(destination)
                destination_owner = self.owners[self.containing(resolved)[0]]
            except DiscoveryError:
                continue
            if source_owner != destination_owner and resolved == destination_owner:
                destinations.add(resolved)
        return sorted(destinations)

    def generator_for_record(self, eligibility, record):
        record_owner = self.owners[self.containing(record)[0]]
        candidates = set()
        for destination in self.callee_entries(eligibility):
            try:
                start, _ = self.containing(destination)
            except DiscoveryError:
                continue
            owner = self.owners[start]
            if destination == owner == record_owner:
                if any(i.address == record for i in self.function(destination)):
                    candidates.add(destination)
        return one(candidates, "Eligibility 调用的 F7 所属函数")

    def method_assignments(self):
        if self.assignments is not None:
            return self.assignments
        from anchors import register_family
        result = []
        # 粗筛只用于取得候选位置，赋值关系由解码后的同基本块数据流决定。
        pattern = re.compile(
            b"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", re.DOTALL
        )
        for section in self.pe.exec_sections():
            raw = self.pe.data[section["raw_ptr"]:section["raw_ptr"] + section["raw_size"]]
            for match in pattern.finditer(raw):
                site = section["va"] + match.start()
                lea = next(self.md.disasm(raw[match.start():match.start() + 15], site), None)
                if lea is None:
                    continue
                if (lea.mnemonic != "lea" or len(lea.operands) != 2
                        or lea.operands[0].type != self.x.X86_OP_REG
                        or lea.operands[0].size != 8 or not self.mem(lea.operands[1], "rip")):
                    continue
                target = lea.address + lea.size + lea.operands[1].mem.disp
                if not self.executable(target):
                    continue
                try:
                    code = self.function(site)
                except DiscoveryError:
                    continue
                instructions = {i.address: i for i in code}
                if site not in instructions:
                    continue
                aliases = {register_family(self, lea.operands[0].reg)}
                address = lea.address + lea.size
                for _ in range(32):
                    store = instructions.get(address)
                    if store is None or not aliases:
                        break
                    if store.mnemonic.startswith("j") or store.mnemonic in (
                            "call", "ret", "retf", "int3", "ud2"):
                        break
                    ops = store.operands
                    if (store.mnemonic == "mov" and len(ops) == 2
                            and self.mem(ops[0], size=8) and ops[0].mem.base
                            and ops[0].mem.base != self.reg("rip") and not ops[0].mem.index
                            and register_family(self, ops[0].mem.base) != "rsp"
                            and ops[1].type == self.x.X86_OP_REG and ops[1].size == 8
                            and register_family(self, ops[1].reg) in aliases
                            and 0 < ops[0].mem.disp < 0x10000):
                        result.append({
                            "site": site, "target": target, "store_site": store.address,
                            "slot": ops[0].mem.disp, "base": ops[0].mem.base,
                            "constructor": self.owners[self.containing(site)[0]],
                        })
                    copied = None
                    if (store.mnemonic == "mov" and len(ops) == 2
                            and all(op.type == self.x.X86_OP_REG and op.size == 8 for op in ops)
                            and register_family(self, ops[1].reg) in aliases):
                        copied = register_family(self, ops[0].reg)
                    _, written = store.regs_access()
                    aliases.difference_update(register_family(self, reg) for reg in written)
                    if copied is not None:
                        aliases.add(copied)
                    address += store.size
        self.assignments = result
        return result


def board_slot_from_submit(image, entry):
    """沿控制流追踪第二参数 Board，核对方法加载及第三/四调用参数。"""
    from anchors import register_family
    code = image.function(entry)
    instructions = {i.address: i for i in code}
    pending = [(entry, {"rdx": ("board",)})]
    visited = set()
    matches = {}
    while pending:
        address, state = pending.pop()
        token = address, tuple(sorted(state.items()))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 20000:
            raise DiscoveryError("Board 提交数据流状态过多。")
        instruction = instructions.get(address)
        if instruction is None:
            continue
        ops = instruction.operands
        current = dict(state)
        value = None
        if instruction.mnemonic == "mov" and len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            if ops[1].type == image.x.X86_OP_REG:
                source = state.get(register_family(image, ops[1].reg))
                if source and ops[0].size == ops[1].size == 8:
                    value = source
            elif (image.mem(ops[1], size=8) and not ops[1].mem.index
                  and state.get(register_family(image, ops[1].mem.base)) == ("board",)
                  and 0 < ops[1].mem.disp < 0x10000):
                value = ("method", ops[1].mem.disp, instruction.address)
        elif instruction.mnemonic == "movzx" and len(ops) == 2:
            if (ops[0].type == image.x.X86_OP_REG and ops[0].size == 4
                    and image.mem(ops[1], size=1) and not ops[1].mem.index
                    and ops[1].mem.disp == 1):
                value = ("selector-byte",)
        _, written = instruction.regs_access()
        for reg in written:
            current.pop(register_family(image, reg), None)
        if value is not None:
            current[register_family(image, ops[0].reg)] = value
        if instruction.mnemonic == "call":
            method = state.get("rax")
            # CFG 间接调用约定由 RAX 提供目标；不接受无关的直接调用。
            indirect = len(ops) == 1 and ops[0].type in (image.x.X86_OP_MEM, image.x.X86_OP_REG)
            if (indirect and method and method[0] == "method"
                    and state.get("r8") == ("board",)
                    and state.get("r9") == ("selector-byte",)):
                matches[method[2]] = (method[1], instruction.address)
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                current.pop(reg, None)
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                pending.append((ops[0].imm, current))
            if instruction.mnemonic == "jmp":
                continue
        pending.append((instruction.address + instruction.size, current))
    site = one(matches, "Board 来源、方法槽及 selector 调用关系")
    slot, call_site = matches[site]
    return slot, site, call_site


def root_lookup_from_generator(image, entry, root_offset):
    """沿路径关联 Root、registry、policy key 与实际 lookup 调用。"""
    from anchors import register_family
    instructions = {i.address: i for i in image.function(entry)}
    pending = [(entry, {"rcx": ("major",)})]
    visited = set()
    matches = set()
    root_loads = set()
    root_reads = set()
    while pending:
        address, state = pending.pop()
        token = address, tuple(sorted(state.items()))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 20000:
            raise DiscoveryError("Root lookup 数据流状态过多。")
        instruction = instructions.get(address)
        if instruction is None:
            continue
        ops = instruction.operands
        # LEA 只计算地址，不是字段读取；写操作也不能作为读取证据。
        if instruction.mnemonic != "lea":
            for operand in ops:
                if (operand.type == image.x.X86_OP_MEM and operand.access & 1
                        and not operand.mem.index
                        and state.get(register_family(image, operand.mem.base)) == ("root",)):
                    if not 0 <= operand.mem.disp < 0x100000 or operand.size not in (1, 2, 4, 8):
                        raise DiscoveryError("Root 字段读取范围或宽度不受支持。")
                    root_reads.add((instruction.address, operand.mem.disp, operand.size))
        value = None
        if len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            if instruction.mnemonic == "mov" and ops[1].type == image.x.X86_OP_REG:
                source = state.get(register_family(image, ops[1].reg))
                if source:
                    pointer = source[0] in ("major", "root", "registry", "lookup")
                    if (pointer and ops[0].size == ops[1].size == 8) or (
                            source[0] == "key" and ops[0].size == ops[1].size == 4):
                        value = source
            elif ops[1].type == image.x.X86_OP_MEM and not ops[1].mem.index:
                memory = ops[1].mem
                base = state.get(register_family(image, memory.base))
                if (instruction.mnemonic == "mov" and base == ("major",)
                        and ops[0].size == ops[1].size == 8 and memory.disp == root_offset):
                    value = ("root",)
                    root_loads.add(instruction.address)
                elif base == ("root",) and 0 < memory.disp < 0x100000:
                    if instruction.mnemonic == "lea" and ops[0].size == 8:
                        value = ("registry", memory.disp, instruction.address)
                    elif instruction.mnemonic == "movzx" and ops[0].size == 4 and ops[1].size == 1:
                        value = ("key", memory.disp, instruction.address)
                    elif instruction.mnemonic == "mov" and ops[0].size == ops[1].size == 8:
                        value = ("lookup", memory.disp, instruction.address)
        current = dict(state)
        _, written = instruction.regs_access()
        for reg in written:
            current.pop(register_family(image, reg), None)
        if value is not None:
            current[register_family(image, ops[0].reg)] = value
        if instruction.mnemonic == "call":
            method = None
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_REG:
                method = state.get(register_family(image, ops[0].reg))
            elif len(ops) == 1 and image.mem(ops[0], "rip", 8):
                # 已支持的 CFG 分派模式以 RAX 提供实际函数指针。
                method = state.get("rax")
            registry = state.get("rcx")
            key = state.get("rdx")
            if (method and method[0] == "lookup"
                    and registry and registry[0] == "registry"
                    and key and key[0] == "key"):
                matches.add((registry, key, method, instruction.address))
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                current.pop(reg, None)
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                pending.append((ops[0].imm, current))
            if instruction.mnemonic == "jmp":
                continue
        pending.append((instruction.address + instruction.size, current))
    registry, key, method, call = one(sorted(matches), "同一 Root 的 registry/key/lookup 调用关系")
    return {
        "registry": registry[1], "key": key[1], "lookup": method[1],
        "registry_site": registry[2], "key_site": key[2], "lookup_site": method[2],
        "call_site": call,
        "root_load_sites": sorted(root_loads),
        "root_reads": sorted(root_reads),
    }


def ctgp_from_generator(image, entry, root_reads, excluded):
    """关联同路径的32位 Root 读取、无效值分支和无符号最小值选择。"""
    from anchors import register_family
    instructions = {i.address: i for i in image.function(entry)}
    read_sites = {(site, width): offset for site, offset, width in root_reads}
    pending = [(entry, {})]
    visited = set()
    matches = {}
    while pending:
        address, state = pending.pop()
        token = address, tuple(sorted(state.items()))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 30000:
            raise DiscoveryError("CTGP 数据流状态过多。")
        instruction = instructions.get(address)
        if instruction is None:
            continue
        ops = instruction.operands
        current = dict(state)
        value = None
        if instruction.mnemonic == "mov" and len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            if ops[0].size == 4:
                if ops[1].type == image.x.X86_OP_REG and ops[1].size == 4:
                    value = state.get(register_family(image, ops[1].reg))
                elif ops[1].type == image.x.X86_OP_IMM:
                    value = ("constant", ops[1].imm & 0xFFFFFFFF)
                elif (image.mem(ops[1], size=4)
                      and (instruction.address, 4) in read_sites):
                    offset = read_sites[instruction.address, 4]
                    if offset not in excluded:
                        value = ("field", offset, instruction.address)
        _, written = instruction.regs_access()
        for reg in written:
            family = register_family(image, reg)
            current.pop(family, None)
            if image.md.reg_name(reg) not in ("eflags", "rflags"):
                current["@write:" + family] = (instruction.address,)
        if any(image.md.reg_name(reg) in ("eflags", "rflags") for reg in written):
            current.pop("@comparison", None)
        if value is not None:
            current[register_family(image, ops[0].reg)] = value
        if instruction.mnemonic == "cmp" and len(ops) == 2:
            arguments = []
            for operand in ops:
                if operand.type == image.x.X86_OP_REG and operand.size == 4:
                    arguments.append(state.get(register_family(image, operand.reg), ("unknown",)))
                elif operand.type == image.x.X86_OP_IMM:
                    arguments.append(("constant", operand.imm & 0xFFFFFFFF))
                else:
                    arguments.append(("unknown",))
            next_instruction = instructions.get(instruction.address + instruction.size)
            for field, sentinel in (arguments, list(reversed(arguments))):
                if (field[0] == "field" and sentinel == ("constant", 0xFFFFFFFF)
                        and next_instruction and next_instruction.mnemonic in ("je", "jne")):
                    current["@sentinel:" + str(field[1])] = ("checked", instruction.address)
            if all(operand.type == image.x.X86_OP_REG and operand.size == 4 for operand in ops):
                current["@comparison"] = (
                    register_family(image, ops[0].reg), register_family(image, ops[1].reg),
                    arguments[0], arguments[1], instruction.address,
                    state.get("@write:" + register_family(image, ops[0].reg)),
                    state.get("@write:" + register_family(image, ops[1].reg)),
                )
        if (instruction.mnemonic in ("cmovb", "cmova") and len(ops) == 2
                and all(operand.type == image.x.X86_OP_REG and operand.size == 4 for operand in ops)):
            comparison = state.get("@comparison")
            if comparison:
                left_reg, right_reg, left, right, compare_site, left_write, right_write = comparison
                destination = register_family(image, ops[0].reg)
                source = register_family(image, ops[1].reg)
                is_min = (
                    instruction.mnemonic == "cmovb" and destination == right_reg and source == left_reg
                ) or (
                    instruction.mnemonic == "cmova" and destination == left_reg and source == right_reg
                )
                # 比较之后寄存器的来源发生变化时不能沿用旧比较关系。
                unchanged = (state.get(left_reg, ("unknown",)) == left
                             and state.get(right_reg, ("unknown",)) == right
                             and state.get("@write:" + left_reg) == left_write
                             and state.get("@write:" + right_reg) == right_write)
                if is_min and unchanged:
                    for origin in (left, right):
                        if origin[0] != "field":
                            continue
                        sentinel = state.get("@sentinel:" + str(origin[1]))
                        if sentinel is not None:
                            matches.setdefault(origin[1], set()).add(
                                (origin[2], sentinel[1], compare_site, instruction.address)
                            )
        if instruction.mnemonic == "call":
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "@comparison"):
                current.pop(reg, None)
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                pending.append((ops[0].imm, current))
            if instruction.mnemonic == "jmp":
                continue
        pending.append((instruction.address + instruction.size, current))
    offset = one(sorted(matches), "无效值检查及无符号最小值关联的 CTGP 字段")
    return offset, sorted(matches[offset])


def root_layout(image, result, evidence):
    d = result["derived"]
    eligibility = image.function(d["RVA_SET_ELIG"])
    generator = image.generator_for_record(eligibility, d["RVA_F7_RECORD"])

    # 不再按 INIT 的固定邻接关系填 eligibility/amount，直接读取原生写指令。
    from anchors import setter_facts, find_f7_record, find_upper_read
    amount_facts = setter_facts(image, d["RVA_SET_AMOUNT"])
    elig_facts = setter_facts(image, d["RVA_SET_ELIG"])
    for facts in (amount_facts, elig_facts):
        if facts["root"] != d["OFF_MAJOR_POWER_ROOT"] or facts["init"][1] != d["OFF_ROOT_INIT"]:
            raise DiscoveryError("setter 的 Root/init 来源与锚点配置不一致。")
    record, record_bytes, submit_site, updater = find_f7_record(image, elig_facts, with_submit=True)
    if record != d["RVA_F7_RECORD"] or record_bytes.hex() != d["_sig_f7_record"]:
        raise DiscoveryError("F7 字节锚点与原生调用链记录不一致。")
    upper_site, upper_bytes, upper, lower = find_upper_read(
        image, amount_facts, elig_facts, record, len(record_bytes),
    )
    if (upper != d["OFF_ROOT_UPPER"] or lower != d["OFF_ROOT_LOWER"]
            or upper_site != d["RVA_F7_UPPER_LOAD"] or upper_bytes.hex() != d["_sig_upper_load"]):
        raise DiscoveryError("F7 上下界原生比较/差值与锚点配置不一致。")
    elig_site, elig, _ = one([s for s in elig_facts["stores"] if s[2] == 1], "eligibility 写字段")
    amount_site, amount_offset, _ = one([s for s in amount_facts["stores"] if s[2] == 4], "amount 写字段")
    active_site, active = one(amount_facts["flags"], "amount-active 写字段")
    lookup_contract = root_lookup_from_generator(image, generator, d["OFF_MAJOR_POWER_ROOT"])
    if not lookup_contract["root_load_sites"]:
        raise DiscoveryError("F7 没有从入口 Major 取得有效 Root。")
    reads = {}
    for site, offset, width in lookup_contract["root_reads"]:
        reads.setdefault((offset, width), []).append(site)
    for offset, width in ((elig, 1), (active, 1), (amount_offset, 4), (d["OFF_ROOT_UPPER"], 4)):
        if (offset, width) not in reads:
            raise DiscoveryError("F7 与原生 setter 的字段访问未交叉匹配。")
    ctgp, ctgp_sites = ctgp_from_generator(
        image, generator, lookup_contract["root_reads"],
        {d["OFF_ROOT_UPPER"], d["OFF_ROOT_LOWER"], amount_offset, elig, active},
    )
    d.update({
        "OFF_ROOT_ELIG": elig, "OFF_ROOT_AMOUNT_ACTIVE": active,
        "OFF_ROOT_AMOUNT": amount_offset, "OFF_ROOT_POLICY_KEY": lookup_contract["key"],
        "OFF_ROOT_CTGP": ctgp,
    })
    layout = {
        "OFF_ROOT_REGISTRY": lookup_contract["registry"],
        "OFF_ROOT_LOOKUP_FN": lookup_contract["lookup"],
    }
    # 其余根字段必须在 F7 中实际读取；只有地址邻近不能放行。
    for name in ("OFF_ROOT_CTGP", "OFF_ROOT_LOWER"):
        if (d[name], 4) not in reads:
            raise DiscoveryError("F7 缺少根字段读取证据：" + name)
    method_slot, method_site, method_call = board_slot_from_submit(image, updater)
    layout["OFF_BOARD_SET_FN"] = method_slot
    evidence.append({
        "rule": "root-setter-f7-dataflow", "generator": generator, "updater": updater,
        "eligibility_write": elig_site, "amount_write": amount_site,
        "active_write": active_site, "key_read": lookup_contract["key_site"],
        "registry_argument": lookup_contract["registry_site"], "lookup_load": lookup_contract["lookup_site"],
        "lookup_call": lookup_contract["call_site"],
        "root_loads": lookup_contract["root_load_sites"],
        "root_reads": lookup_contract["root_reads"],
        "ctgp_read_sentinel_compare_select": ctgp_sites,
        "method_load": method_site, "method_call": method_call,
        "record_submit": submit_site,
    })
    return layout


def selector_layout(image, helper):
    from anchors import register_family
    code = {i.address: i for i in image.function(helper)}
    pending = [(helper, {"r9": ("selector-input",), "r8": ("board",)}, None)]
    visited, dispatches = set(), set()
    dispatch_sites = {}
    while pending:
        address, state, comparison = pending.pop()
        token = address, tuple(sorted(state.items())), comparison
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 20000:
            raise DiscoveryError("selector 分派数据流状态过多。")
        instruction = code.get(address)
        if instruction is None:
            continue
        ops = instruction.operands
        value = None
        if len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            if ops[1].type == image.x.X86_OP_REG:
                source = state.get(register_family(image, ops[1].reg))
                if instruction.mnemonic == "mov" and source:
                    if ops[0].size == ops[1].size == 8 or (
                            source[0] == "selector" and ops[0].size == ops[1].size == 4):
                        value = source
                elif (instruction.mnemonic == "movzx" and source == ("selector-input",)
                      and ops[0].size == 4 and ops[1].size == 1):
                    value = ("selector", None)
            elif (instruction.mnemonic == "lea" and image.mem(ops[1], "rip")
                  and ops[0].size == 8
                  and instruction.address + instruction.size + ops[1].mem.disp == 0):
                value = ("image-base",)
            elif (instruction.mnemonic == "mov" and ops[0].size == 4
                  and image.mem(ops[1], size=4) and ops[1].mem.scale == 4):
                memory = ops[1].mem
                index = state.get(register_family(image, memory.index))
                if (state.get(register_family(image, memory.base)) == ("image-base",)
                        and index and index[0] == "selector" and index[1] is not None):
                    value = ("case-rva", memory.disp, index[1] + 1)
            if instruction.mnemonic == "add" and ops[1].type == image.x.X86_OP_REG:
                left = state.get(register_family(image, ops[0].reg))
                right = state.get(register_family(image, ops[1].reg))
                if (ops[0].size == ops[1].size == 8 and left and left[0] == "case-rva"
                        and right == ("image-base",)):
                    value = ("dispatch", left[1], left[2])
        current = dict(state)
        _, written = instruction.regs_access()
        for reg in written:
            current.pop(register_family(image, reg), None)
        if value is not None:
            current[register_family(image, ops[0].reg)] = value
        next_comparison = comparison
        if any(image.md.reg_name(reg) in ("eflags", "rflags") for reg in written):
            next_comparison = None
        if (instruction.mnemonic == "cmp" and len(ops) == 2
                and ops[0].type == image.x.X86_OP_REG and ops[0].size == 4
                and ops[1].type == image.x.X86_OP_IMM and 3 <= ops[1].imm < 64):
            source = state.get(register_family(image, ops[0].reg))
            if source and source[0] == "selector":
                next_comparison = ops[1].imm
        if instruction.mnemonic == "jmp" and len(ops) == 1 and ops[0].type == image.x.X86_OP_REG:
            target = state.get(register_family(image, ops[0].reg))
            if target and target[0] == "dispatch":
                board_registers = tuple(sorted(reg for reg, origin in state.items()
                                               if origin == ("board",)))
                dispatches.add((target[1], target[2], board_registers))
                dispatch_sites.setdefault((target[1], target[2], board_registers), set()).add(
                    instruction.address,
                )
            continue
        if instruction.mnemonic == "call":
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                current.pop(reg, None)
            next_comparison = None
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) != 1 or ops[0].type != image.x.X86_OP_IMM:
                continue
            taken, fallthrough = dict(current), dict(current)
            if next_comparison is not None and instruction.mnemonic in ("ja", "jnbe", "jbe", "jna"):
                bounded = fallthrough if instruction.mnemonic in ("ja", "jnbe") else taken
                for reg, origin in bounded.items():
                    if origin[0] == "selector":
                        bounded[reg] = ("selector", next_comparison)
            pending.append((ops[0].imm, taken, None))
            if instruction.mnemonic == "jmp":
                continue
            current = fallthrough
            next_comparison = None
        pending.append((instruction.address + instruction.size, current, next_comparison))
    table, count, board_registers = one(sorted(dispatches), "selector 参数与范围保护的跳转表")
    dispatch_site = one(
        dispatch_sites[(table, count, board_registers)], "selector 跳转表实际分派位置",
    )
    if not hasattr(image, "selector_dispatch_sites"):
        image.selector_dispatch_sites = {}
    image.selector_dispatch_sites[helper] = dispatch_site
    if not board_registers:
        raise DiscoveryError("selector 分派前 Board 对象来源已经失效。")
    cases = struct.unpack("<{}I".format(count), image.read(table, count * 4))
    result = {}
    for selector in (2, 3):
        try:
            owner = image.owners[image.containing(cases[selector])[0]]
        except DiscoveryError as error:
            raise DiscoveryError("selector 分支没有有效函数归属。") from error
        if owner != image.owners[image.containing(helper)[0]]:
            raise DiscoveryError("selector 分支不在基础方法内。")
        ins = next(image.md.disasm(image.read(cases[selector], 15), cases[selector]), None)
        if (not ins or ins.mnemonic != "lea" or not image.mem(ins.operands[1])
                or ins.operands[1].mem.index
                or register_family(image, ins.operands[1].mem.base) not in board_registers):
            raise DiscoveryError("selector 分支没有直接取得 Board 槽。")
        result["OFF_SELECTOR" + str(selector)] = ins.operands[1].mem.disp
    return result, table


def source_slot_layout(image, entry, parameter_registers=("rdx", "r8", "r9")):
    """从源数组原生写入函数提取槽字段；不沿用固定字段位移。"""
    from anchors import register_family
    code = {i.address: i for i in image.function(entry)}
    slot_register, source_register, value_register = parameter_registers
    pending = [(entry, {
        slot_register: ("slot",), source_register: ("source",), value_register: ("value",),
    })]
    visited = set()
    ids, values, effective, increments, count_reads, byte_reads, capacities, insertions = (
        set() for _ in range(8)
    )
    while pending:
        address, state = pending.pop()
        token = address, tuple(sorted(state.items()))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 20000:
            raise DiscoveryError("selector 源数组访问数据流状态过多。")
        instruction = code.get(address)
        if instruction is None:
            continue
        ops = instruction.operands
        field = None
        for op in ops:
            if (op.type == image.x.X86_OP_MEM and
                    state.get(register_family(image, op.mem.base)) == ("slot",)):
                field = op
                break
        value = None
        if field is not None:
            memory = field.mem
            if memory.disp < 0 or memory.disp >= 0x10000:
                raise DiscoveryError("selector 槽字段位移无效。")
            if not memory.index:
                if field.size == 1 and field.access & 1:
                    byte_reads.add(memory.disp)
                if instruction.mnemonic == "inc" and field.size == 1:
                    increments.add(memory.disp)
                if (instruction.mnemonic == "movzx" and len(ops) == 2
                        and field is ops[1] and field.size == 1
                        and ops[0].type == image.x.X86_OP_REG):
                    count_reads.add(memory.disp)
                    byte_reads.add(memory.disp)
                    value = ("slot-byte", memory.disp)
                if (instruction.mnemonic == "mov" and len(ops) == 2
                        and field is ops[0] and field.size == 4):
                    effective.add(memory.disp)
            elif len(ops) == 2 and memory.scale in (1, 2, 4, 8):
                source = (state.get(register_family(image, ops[1].reg))
                          if ops[1].type == image.x.X86_OP_REG else None)
                index = state.get(
                    register_family(image, memory.index),
                    ("index-input", register_family(image, memory.index)),
                )
                if instruction.mnemonic == "cmp" and field is ops[0] and field.size == 1 and source == ("source",):
                    ids.add((memory.disp, memory.scale, index))
                if instruction.mnemonic == "mov" and field is ops[0] and field.size == 4 and source == ("value",):
                    values.add((memory.disp, memory.scale, index))
                    guard = state.get("@capacity")
                    if guard and index == ("slot-byte", guard[0]):
                        insertions.add(("value", memory.disp, memory.scale, guard))
                if instruction.mnemonic == "mov" and field is ops[0] and field.size == 1 and source == ("source",):
                    guard = state.get("@capacity")
                    if guard and index == ("slot-byte", guard[0]):
                        insertions.add(("id", memory.disp, memory.scale, guard))
        next_comparison = None
        if (instruction.mnemonic == "cmp" and len(ops) == 2
                and ops[0].type == image.x.X86_OP_REG and ops[1].type == image.x.X86_OP_IMM):
            origin = state.get(register_family(image, ops[0].reg))
            if origin and origin[0] == "slot-byte" and 0 < ops[1].imm <= 64:
                next_comparison = (origin[1], ops[1].imm)
            else:
                next_comparison = None
        if (instruction.mnemonic in ("mov", "movzx") and len(ops) == 2
                and all(op.type == image.x.X86_OP_REG for op in ops)):
            origin = state.get(register_family(image, ops[1].reg))
            if origin is not None:
                if origin == ("slot",) and ops[0].size == ops[1].size == 8:
                    value = origin
                elif origin[0] in ("source", "value", "slot-byte", "index", "index-input"):
                    # source 为字节参数，value 为32位参数，不能截断 value。
                    if origin[0] != "value" or ops[0].size >= 4 and ops[1].size >= 4:
                        value = origin
        current = dict(state)
        if field is not None and field.access & 2 and not field.mem.index:
            for key in ("@capacity", "@capacity-comparison"):
                guard = current.get(key)
                if guard and field.mem.disp <= guard[0] < field.mem.disp + field.size:
                    current.pop(key, None)
        _, writes = instruction.regs_access()
        for reg in writes:
            family = register_family(image, reg)
            current[family] = ("index", instruction.address)
        if any(image.md.reg_name(reg) in ("eflags", "rflags") for reg in writes):
            current.pop("@capacity-comparison", None)
        if instruction.mnemonic == "cmp" and next_comparison is not None:
            current["@capacity-comparison"] = next_comparison
        if value is not None and ops[0].type == image.x.X86_OP_REG:
            current[register_family(image, ops[0].reg)] = value
        if instruction.mnemonic == "call":
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                current.pop(reg, None)
            current.pop("@capacity", None)
            current.pop("@capacity-comparison", None)
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                taken, fallthrough = dict(current), dict(current)
                comparison = state.get("@capacity-comparison")
                if comparison is not None and instruction.mnemonic in ("jae", "jnb", "jb", "jnae"):
                    bounded = fallthrough if instruction.mnemonic in ("jae", "jnb") else taken
                    bounded["@capacity"] = comparison
                    capacities.add(comparison)
                taken.pop("@capacity-comparison", None)
                fallthrough.pop("@capacity-comparison", None)
                pending.append((ops[0].imm, taken))
                current = fallthrough
            if instruction.mnemonic == "jmp":
                continue
        pending.append((instruction.address + instruction.size, current))
    count, maximum = one(sorted(p for p in capacities if p[0] in increments and p[0] in count_reads),
                         "源数组计数、自增与容量约束")
    mode = one(sorted(byte_reads - {count}), "源数组 mode 字段")
    matched = {
        (id_offset, stride, value_offset, value_stride)
        for id_offset, stride, index in ids
        for value_offset, value_stride, value_index in values
        if index == value_index
    }
    id_offset, stride, value_offset, value_stride = one(
        sorted(matched), "同一下标来源的源 ID/值数组位移与步长",
    )
    for kind, offset in (("id", id_offset), ("value", value_offset)):
        if (kind, offset, stride, (count, maximum)) not in insertions:
            raise DiscoveryError("源数组插入缺少计数下标及容量分支保护：" + kind)
    effective_offset = one(sorted(effective), "源数组 effective 字段")
    if (stride != value_stride or value_offset < id_offset + 1
            or value_offset + 4 > id_offset + stride):
        raise DiscoveryError("源 ID/值字段不能组成同一步长的数组元素。")
    occupied = [(mode, mode + 1), (count, count + 1),
                (effective_offset, effective_offset + 4),
                (id_offset, id_offset + maximum * stride)]
    ordered = sorted(occupied)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise DiscoveryError("selector 槽字段区间重叠。")
    return {
        "SLOT_MODE": mode, "SLOT_COUNT": count, "SLOT_EFFECTIVE": effective_offset,
        "SLOT_SOURCE_ID0": id_offset, "SLOT_SOURCE_VALUE0": value_offset,
        "SLOT_SOURCE_STRIDE": stride, "SLOT_SOURCE_MAX": maximum,
    }


def slot_writer_contract(image, helper, writer, selectors, table, parameter_registers):
    """从基础方法入口追踪 selector 槽及来源/值，不凭被调函数外观选择参数约定。"""
    from anchors import register_family
    cases = struct.unpack("<4I", image.read(table, 16))
    owner = image.owners[image.containing(helper)[0]]
    pending = [(helper, {
        "rcx": ("major",), "rdx": ("root",), "r8": ("board",),
        "r9": ("selector",), "@rsp": (0,),
    })]
    visited, matches = set(), set()
    while pending:
        address, state = pending.pop()
        token = address, tuple(sorted(state.items()))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 20000:
            raise DiscoveryError("源数组调用参数数据流状态过多。")
        try:
            if image.owners[image.containing(address)[0]] != owner:
                continue
            interval = image.containing(address)
            instruction = next(image.md.disasm(
                image.read(address, min(15, interval[1] - address)), address,
            ), None)
        except DiscoveryError:
            continue
        if instruction is None:
            raise DiscoveryError("源数组调用路径无法解码。")
        ops = instruction.operands
        current = dict(state)
        stack = state.get("@rsp", (None,))[0]
        value = None
        if len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            if instruction.mnemonic in ("mov", "movzx") and ops[1].type == image.x.X86_OP_REG:
                origin = state.get(register_family(image, ops[1].reg))
                if origin:
                    if origin[0] in ("major", "root", "board", "slot"):
                        if instruction.mnemonic == "mov" and ops[0].size == ops[1].size == 8:
                            value = origin
                    elif origin[0] in ("source", "value", "selector"):
                        minimum = 4 if origin[0] == "value" else 1
                        if ops[0].size >= ops[1].size >= minimum:
                            value = origin
            elif instruction.mnemonic in ("mov", "movzx") and image.mem(ops[1], "rsp") and not ops[1].mem.index and stack is not None:
                position = stack + ops[1].mem.disp
                if position == 0x28 and ops[1].size in (1, 4):
                    value = ("source",)
                elif position == 0x30 and ops[1].size == 4:
                    value = ("value",)
                else:
                    value = state.get("@stack:" + str(position))
            elif instruction.mnemonic == "lea" and image.mem(ops[1]) and not ops[1].mem.index:
                origin = state.get(register_family(image, ops[1].mem.base))
                if origin == ("board",) and ops[0].size == 8:
                    selector = state.get("@case")
                    if selector and ops[1].mem.disp == selectors["OFF_SELECTOR" + str(selector[0])]:
                        value = ("slot", selector[0])
        _, writes = instruction.regs_access()
        for register in writes:
            current.pop(register_family(image, register), None)
        if value is not None:
            current[register_family(image, ops[0].reg)] = value
        if instruction.mnemonic in ("push", "pop") and stack is not None:
            current["@rsp"] = (stack + (-8 if instruction.mnemonic == "push" else 8),)
        elif (instruction.mnemonic in ("sub", "add") and len(ops) == 2
              and ops[0].type == image.x.X86_OP_REG and ops[0].reg == image.reg("rsp")
              and ops[1].type == image.x.X86_OP_IMM and stack is not None):
            current["@rsp"] = (stack + ops[1].imm * (-1 if instruction.mnemonic == "sub" else 1),)
        elif image.reg("rsp") in writes and instruction.mnemonic != "call":
            current.pop("@rsp", None)
        if (ops and image.mem(ops[0], "rsp") and not ops[0].mem.index
                and ops[0].access & 2 and stack is not None):
            position = stack + ops[0].mem.disp
            key = "@stack:" + str(position)
            current.pop(key, None)
            if instruction.mnemonic == "mov" and len(ops) == 2 and ops[1].type == image.x.X86_OP_REG:
                origin = state.get(register_family(image, ops[1].reg))
                if origin and (ops[0].size == 8 or origin[0] in ("source", "value")):
                    current[key] = origin
        if instruction.mnemonic == "call":
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                try:
                    destination, _ = image.resolve_direct_entry(ops[0].imm)
                except DiscoveryError:
                    destination = None
                slot_reg, source_reg, value_reg = parameter_registers
                slot = state.get(slot_reg)
                if (destination == writer and slot and slot[0] == "slot"
                        and state.get(source_reg) == ("source",)
                        and state.get(value_reg) == ("value",)
                        and (slot_reg == "rcx" or state.get("rcx") == ("major",))):
                    matches.add((slot[1], instruction.address))
            for register in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                current.pop(register, None)
            for key in list(current):
                if key.startswith("@stack:"):
                    current.pop(key, None)
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) != 1:
                continue
            if ops[0].type == image.x.X86_OP_IMM:
                pending.append((ops[0].imm, current))
            elif instruction.mnemonic == "jmp" and ops[0].type == image.x.X86_OP_REG:
                # selector_layout 已独立验证这张表及其 selector 2/3 入口。
                if address == getattr(image, "selector_dispatch_sites", {}).get(helper):
                    for selector in (2, 3):
                        branch = dict(current)
                        branch["@case"] = (selector,)
                        pending.append((cases[selector], branch))
            if instruction.mnemonic == "jmp":
                continue
        pending.append((instruction.address + instruction.size, current))
    if {selector for selector, _ in matches} != {2, 3}:
        raise DiscoveryError("未确认 selector 2/3 将原始来源和值传给源数组函数",
                             {"writer": writer, "parameter_registers": parameter_registers,
                              "matching_calls": sorted(matches)})
    return {"parameter_registers": list(parameter_registers), "selector_calls": sorted(matches)}


def board_wrapper_contract(image, entry, helper):
    """跟踪 Board 类型查询返回值，不固定保存该对象的寄存器。"""
    from anchors import register_family
    code = image.function(entry)
    instructions = {i.address: i for i in code}
    pending = [(entry, {
        "rcx": ("major",), "rdx": ("root",), "r8": ("board",),
        "r9": ("selector",), "@rsp": (0,),
    })]
    visited, casts, callbacks = set(), set(), set()
    callback_loads, callback_attempts = set(), set()
    helper_calls = set()
    while pending:
        address, state = pending.pop()
        token = address, tuple(sorted(state.items()))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 20000:
            raise DiscoveryError("Board wrapper 数据流状态过多。")
        instruction = instructions.get(address)
        if instruction is None:
            continue
        ops = instruction.operands
        current = dict(state)
        value = None
        stack_offset = state.get("@rsp", (None,))[0]
        if instruction.mnemonic in ("mov", "movzx") and len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            if ops[1].type == image.x.X86_OP_REG:
                source = state.get(register_family(image, ops[1].reg))
                if source:
                    if source[0] == "type-id":
                        if ops[0].size == ops[1].size == 1:
                            value = source
                    elif source[0] in ("selector", "source", "value"):
                        if (source[0] != "value" or ops[1].size >= 4) and ops[0].size >= ops[1].size:
                            value = source
                    elif instruction.mnemonic == "mov" and ops[0].size == ops[1].size == 8:
                        value = source
            elif instruction.mnemonic == "mov" and ops[1].type == image.x.X86_OP_IMM and ops[0].size in (1, 4, 8):
                value = ("type-id", ops[1].imm & 0xFF)
            elif image.mem(ops[1], "rsp") and not ops[1].mem.index and stack_offset is not None:
                position = stack_offset + ops[1].mem.disp
                if position == 0x28 and ops[1].size in (1, 4):
                    value = ("source",)
                elif position == 0x30 and ops[1].size == 4:
                    value = ("value",)
                else:
                    value = state.get("@stack:" + str(position))
            elif instruction.mnemonic == "mov" and image.mem(ops[1], size=8) and not ops[1].mem.index:
                source = state.get(register_family(image, ops[1].mem.base))
                if source == ("board",) and ops[1].mem.disp == 8 and ops[0].size == 8:
                    value = ("type-table",)
                elif source == ("type-table",) and ops[1].mem.disp == 0 and ops[0].size == 8:
                    value = ("type-query",)
                elif source and source[0] == "typed-board" and ops[0].size == 8:
                    value = ("callback", source, ops[1].mem.disp, instruction.address)
                    callback_loads.add((source[1], ops[1].mem.disp, instruction.address))
        _, writes = instruction.regs_access()
        for reg in writes:
            current.pop(register_family(image, reg), None)
        if value is not None:
            current[register_family(image, ops[0].reg)] = value
        if instruction.mnemonic in ("push", "pop") and stack_offset is not None:
            current["@rsp"] = (stack_offset + (-8 if instruction.mnemonic == "push" else 8),)
        elif (instruction.mnemonic in ("sub", "add") and len(ops) == 2
              and ops[0].type == image.x.X86_OP_REG and ops[0].reg == image.reg("rsp")
              and ops[1].type == image.x.X86_OP_IMM and stack_offset is not None):
            current["@rsp"] = (
                stack_offset + ops[1].imm * (-1 if instruction.mnemonic == "sub" else 1),
            )
        elif image.reg("rsp") in writes and instruction.mnemonic != "call":
            current.pop("@rsp", None)
        if (len(ops) >= 1 and image.mem(ops[0], "rsp") and ops[0].access & 2
                and not ops[0].mem.index and stack_offset is not None):
            position = stack_offset + ops[0].mem.disp
            for key in list(current):
                if key.startswith("@stack:") and position < int(key[7:]) + 4 and int(key[7:]) < position + ops[0].size:
                    current.pop(key, None)
            if instruction.mnemonic == "mov" and len(ops) == 2 and ops[1].type == image.x.X86_OP_REG:
                source = state.get(register_family(image, ops[1].reg))
                if ((source == ("source",) and ops[0].size in (1, 4))
                        or (source == ("value",) and ops[0].size == 4)):
                    current["@stack:" + str(position)] = source
        if instruction.mnemonic == "call":
            indirect = len(ops) == 1 and ops[0].type in (image.x.X86_OP_REG, image.x.X86_OP_MEM)
            returned = None
            target = None
            if indirect:
                if ops[0].type == image.x.X86_OP_REG:
                    target = state.get(register_family(image, ops[0].reg))
                elif image.is_guard_dispatch(instruction):
                    target = state.get("rax")
                elif (image.mem(ops[0], size=8) and not ops[0].mem.index):
                    # 支持 call [typed_board+slot]，不要求先加载到寄存器。
                    source = state.get(register_family(image, ops[0].mem.base))
                    if source and source[0] == "typed-board":
                        target = ("callback", source, ops[0].mem.disp, instruction.address)
                        callback_loads.add((source[1], ops[0].mem.disp, instruction.address))
            if target == ("type-query",) and state.get("rcx") == ("board",):
                type_id = state.get("rdx")
                if type_id and type_id[0] == "type-id":
                    casts.add((instruction.address, type_id[1]))
                    returned = ("typed-board", type_id[1], instruction.address)
            if target and target[0] == "callback":
                callback_attempts.add((
                    target[1][1], target[2], target[3], instruction.address,
                    state.get("r8") == target[1],
                ))
            arguments_match = (
                stack_offset is not None and state.get("rcx") == ("major",)
                and state.get("rdx") == ("root",) and state.get("r9") == ("selector",)
                and state.get("@stack:" + str(stack_offset + 0x20)) == ("source",)
                and state.get("@stack:" + str(stack_offset + 0x28)) == ("value",)
            )
            if (target and target[0] == "callback" and arguments_match
                    and state.get("r8") == target[1] and state.get("@helper")):
                callbacks.add((target[1][1], target[2], target[3], instruction.address))
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                try:
                    destination, _ = image.resolve_direct_entry(ops[0].imm)
                except DiscoveryError:
                    destination = None
                if destination == helper and arguments_match and state.get("r8") == ("board",):
                    helper_calls.add(instruction.address)
                    current["@helper"] = (instruction.address,)
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                current.pop(reg, None)
            # 调用的出参区可被被调函数改写，不能把旧栈参数沿用到下一次调用。
            for key in list(current):
                if key.startswith("@stack:"):
                    current.pop(key, None)
            if returned:
                current["rax"] = returned
        if instruction.mnemonic in ("ret", "retf", "int3", "ud2"):
            continue
        if instruction.mnemonic.startswith("j"):
            if len(ops) == 1 and ops[0].type == image.x.X86_OP_IMM:
                pending.append((ops[0].imm, current))
            if instruction.mnemonic == "jmp":
                continue
        pending.append((instruction.address + instruction.size, current))
    details = {
        "entry": entry, "type_queries": sorted(casts),
        "callback_calls": sorted(callbacks), "base_setter_calls": sorted(helper_calls),
        "callback_pointer_accesses": sorted(callback_loads),
        "callback_attempts": sorted(callback_attempts),
    }
    if {type_id for _, type_id in casts} != {0x14}:
        raise DiscoveryError("不是已支持的单类型 0x14 Board wrapper", details)
    if not helper_calls:
        raise DiscoveryError("未确认调用 Board 基础 setter", details)
    slots = {slot for type_id, slot, _, _ in callbacks
             if type_id == 0x14 and 0 < slot < 0x10000 and slot % 8 == 0}
    if len(slots) != 1:
        observed = ", ".join(
            "类型0x{:X}/槽0x{:X}/读取0x{:X}/调用0x{:X}/对象参数{}".format(
                type_id, slot, load, call, "匹配" if object_matches else "不匹配"
            )
            for type_id, slot, load, call, object_matches in sorted(callback_attempts)[:8]
        )
        loads = ", ".join(
            "类型0x{:X}/槽0x{:X}@0x{:X}".format(type_id, slot, site)
            for type_id, slot, site in sorted(callback_loads)[:8]
        )
        raise DiscoveryError(
            "未确认类型查询返回对象的唯一回调槽及全部六个参数；观察调用：{}；观察指针访问：{}".format(
                observed or "未识别", loads or "未识别"
            ), details,
        )
    details["callback_slot"] = next(iter(slots))
    return details


def board_method(image, layout, evidence, source_layout=None):
    candidates = [a for a in image.method_assignments() if a["slot"] == layout["OFF_BOARD_SET_FN"]]
    helpers = {}
    for a in candidates:
        try:
            values, table = selector_layout(image, a["target"])
        except DiscoveryError:
            continue
        helpers[a["target"]] = (values, table, a)
    helper = one(helpers, "具有 selector 2/3 分派的 Board 基础 setter")
    matches = []
    rejected = []
    contracts = {}
    for a in candidates:
        if a["target"] == helper:
            continue
        try:
            body_entry, jump_chain = image.resolve_direct_entry(a["target"])
            if body_entry == helper:
                continue
            code = image.function(body_entry)
        except DiscoveryError as error:
            rejected.append({"entry": a["target"], "reason": str(error)})
            continue
        if code[0].address != body_entry or helper not in image.callee_entries(code):
            rejected.append({
                "entry": a["target"], "body_entry": body_entry,
                "reason": "未确认入口及基础 setter 调用关系",
            })
            continue
        try:
            contract = board_wrapper_contract(image, body_entry, helper)
        except DiscoveryError as error:
            candidate_details = dict(error.diag)
            # 仅进入可选诊断文件，便于离线辨别不同版本的真实调用形式。
            candidate_details["instructions"] = [
                {"rva": "0x{:X}".format(i.address), "bytes": bytes(i.bytes).hex(),
                 "instruction": "{} {}".format(i.mnemonic, i.op_str).strip()}
                for i in code[:192]
            ]
            candidate_details["instruction_count"] = len(code)
            candidate_details["instructions_truncated"] = len(code) > 192
            rejected.append({
                "entry": a["target"], "body_entry": body_entry,
                "reason": str(error), "details": candidate_details,
            })
            continue
        contract["entry_jump_chain"] = jump_chain
        contracts[a["target"]] = contract
        matches.append(a)
    if len(matches) != 1:
        details = {
            "base_setter": helper, "method_slot": layout["OFF_BOARD_SET_FN"],
            "matching_entries": [a["target"] for a in matches],
            "rejected_candidates": rejected,
        }
        summary = "; ".join("0x{:X}: {}".format(item["entry"], item["reason"])
                            for item in rejected[:8])
        raise DiscoveryError(
            "Board type-0 setter：需要唯一结果，实际 {} 个。候选排除原因：{}".format(
                len(matches), summary or "没有可关联的初始化赋值"
            ), details,
        )
    chosen = matches[0]
    selectors, table, base_assignment = helpers[helper]
    layout.update(selectors)
    helper_code = image.function(helper)
    slot_writers = {}
    slot_writer_contracts = {}
    rejected_writers = []
    slot_writer_calls = image.callee_entries(helper_code)
    for call in slot_writer_calls:
        try:
            body = image.function(call)
        except DiscoveryError as error:
            rejected_writers.append({
                "entry": call, "stage": "函数边界与指令解析",
                "reason": str(error), "details": error.diag,
            })
            continue
        attempts, accepted = [], []
        for parameter_registers in (("rdx", "r8", "r9"), ("rcx", "rdx", "r8")):
            try:
                fields = source_slot_layout(image, call, parameter_registers)
                contract = slot_writer_contract(image, helper, call, selectors, table, parameter_registers)
                accepted.append((fields, contract))
            except DiscoveryError as error:
                attempts.append({
                    "parameter_registers": list(parameter_registers),
                    "reason": str(error), "details": error.diag,
                })
        if len(accepted) != 1:
            rejected_writers.append({
                "entry": call, "stage": "selector 源数组布局识别",
                "reason": "源数组布局及调用参数：需要唯一结果，实际 {} 个".format(len(accepted)),
                "details": {"attempts": attempts},
                "instructions": [
                    {"rva": "0x{:X}".format(i.address), "bytes": bytes(i.bytes).hex(),
                     "instruction": "{} {}".format(i.mnemonic, i.op_str).strip()}
                    for i in body[:192]
                ],
                "instruction_count": len(body), "instructions_truncated": len(body) > 192,
            })
            continue
        slot_writers[call], slot_writer_contracts[call] = accepted[0]
    if len(slot_writers) != 1:
        details = {
            "base_setter": helper, "type0_setter": chosen["target"],
            "method_slot": layout["OFF_BOARD_SET_FN"],
            "wrapper_contract": contracts[chosen["target"]],
            "callee_entries": slot_writer_calls, "matching_entries": sorted(slot_writers),
            "rejected_candidates": rejected_writers,
            "helper_instructions": [
                {"rva": "0x{:X}".format(i.address), "bytes": bytes(i.bytes).hex(),
                 "instruction": "{} {}".format(i.mnemonic, i.op_str).strip()}
                for i in helper_code[:192]
            ],
            "helper_instruction_count": len(helper_code),
            "helper_instructions_truncated": len(helper_code) > 192,
        }
        summary = "; ".join("0x{:X}: {}".format(item["entry"], item["reason"])
                            for item in rejected_writers[:8])
        raise DiscoveryError(
            "selector 源数组布局与容量访问者：需要唯一结果，实际 {} 个。候选排除原因：{}".format(
                len(slot_writers), summary or "没有可关联的调用入口"
            ), details,
        )
    slot_writer = one(slot_writers, "selector 源数组布局与容量访问者")
    if source_layout is not None:
        source_layout.update(slot_writers[slot_writer])
    evidence.append({
        "rule": "board-initializer-selector-dispatch", "base_setter": helper,
        "base_assignment": base_assignment["site"], "selector_table": table,
        "type0_setter": chosen["target"], "type0_assignment": chosen["site"],
        "wrapper_contract": contracts[chosen["target"]],
        "candidate_assignments": len(candidates),
        "slot_writer": slot_writer,
        "source_layout": slot_writers[slot_writer],
        "slot_writer_contract": slot_writer_contracts[slot_writer],
        "boundary": "当前仅识别 type-0 wrapper 的 0x14 类型分派族；不是所有类型的 ABI 证明。",
    })
    return {
        "RVA_BOARD_TYPE0_SET": chosen["target"],
        "signature": image.read(chosen["target"], 15).hex(),
    }


def gpu_table_layout(image, result, evidence):
    start = result["derived"]["RVA_GPU_REGISTRY_FN"]
    section = image.pe.containing_section(start)
    # 叶函数可能没有异常目录项；从已识别入口解码至首个 RET。
    window = image.read(start, min(0x100, section["va"] + section["raw_size"] - start))
    code = []
    for i in image.md.disasm(window, start):
        code.append(i)
        if i.mnemonic == "ret":
            break
    global_register = one(
        [i.operands[0].reg for i in code if i.mnemonic == "mov" and len(i.operands) == 2
         and image.mem(i.operands[1], "rip", 8)
         and i.address + i.size + i.operands[1].mem.disp == result["derived"]["RVA_GPU_GLOBAL"]],
        "GPU 全局对象寄存器",
    )
    table_reg = one(
        [i.operands[0].reg for i in code if i.mnemonic == "mov" and len(i.operands) == 2
         and image.mem(i.operands[1], size=8)
         and i.operands[1].mem.base == global_register
         and i.operands[1].mem.disp == result["derived"]["OFF_GLOBAL_GPU_TABLE"]],
        "GPU table 寄存器",
    )
    count_load = one(
        [i for i in code if i.mnemonic == "mov" and len(i.operands) == 2
         and i.operands[1].type == image.x.X86_OP_MEM
         and i.operands[1].mem.base == table_reg and not i.operands[1].mem.index
         and i.operands[1].size == 4], "GPU table count",
    )
    from anchors import register_family
    canonical = lambda reg: register_family(image, reg)
    count_reg = canonical(count_load.operands[0].reg)
    loops = []
    for index, increment in enumerate(code[:-2]):
        ops = increment.operands
        if increment.mnemonic != "inc" or len(ops) != 1 or ops[0].type != image.x.X86_OP_REG:
            continue
        comparison, branch = code[index + 1:index + 3]
        counter = canonical(ops[0].reg)
        if (comparison.mnemonic != "cmp" or len(comparison.operands) != 2
                or any(op.type != image.x.X86_OP_REG for op in comparison.operands)
                or canonical(comparison.operands[0].reg) != counter
                or canonical(comparison.operands[1].reg) != count_reg
                or branch.mnemonic != "jb" or branch.operands[0].type != image.x.X86_OP_IMM):
            continue
        loop_start = branch.operands[0].imm
        if not count_load.address < loop_start < increment.address:
            continue
        initialized = False
        for previous in code:
            if previous.address >= loop_start:
                break
            _, writes = previous.regs_access()
            if not any(canonical(reg) == counter for reg in writes):
                continue
            op = previous.operands
            initialized = (
                previous.mnemonic == "xor" and len(op) == 2
                and all(o.type == image.x.X86_OP_REG for o in op)
                and canonical(op[0].reg) == canonical(op[1].reg) == counter
            ) or (
                previous.mnemonic == "mov" and len(op) == 2
                and op[1].type == image.x.X86_OP_IMM and op[1].imm == 0
            )
        if initialized:
            loops.append((loop_start, increment.address, counter))
    loop_start, loop_end, counter = one(loops, "GPU 表计数约束的归零自增循环")
    by_address = {i.address: i for i in code}
    pending = [(loop_start, {counter: (1, 0)})]
    visited = set()
    ptrs, ids = set(), set()
    while pending:
        address, expressions = pending.pop()
        token = (address, tuple(sorted(expressions.items())))
        if token in visited or not loop_start <= address < loop_end:
            continue
        visited.add(token)
        if len(visited) > 4096:
            raise DiscoveryError("GPU 索引数据流状态过多。")
        i = by_address.get(address)
        if i is None:
            raise DiscoveryError("GPU 循环分支没有落在指令边界。")
        ops = i.operands
        _, written_registers = i.regs_access()
        if any(canonical(reg) == canonical(table_reg) for reg in written_registers):
            raise DiscoveryError("GPU 索引循环覆盖了表对象寄存器，当前规则不能继续追踪。")
        if any(canonical(reg) == count_reg for reg in written_registers):
            raise DiscoveryError("GPU 索引循环覆盖了表计数，不能沿用初始循环边界。")
        for op in ops:
            if (op.type != image.x.X86_OP_MEM or op.mem.base != table_reg
                    or not op.mem.index or op.access & 2):
                continue
            expression = expressions.get(canonical(op.mem.index))
            if expression is None:
                continue
            stride = expression[0] * op.mem.scale
            offset = expression[1] * op.mem.scale + op.mem.disp
            if i.mnemonic == "mov" and op.size == 8:
                ptrs.add((offset, stride, i.address))
            if i.mnemonic == "cmp" and op.size == 4:
                ids.add((offset, stride, i.address))
        updated = dict(expressions)
        _, writes = i.regs_access()
        for reg in writes:
            updated.pop(canonical(reg), None)
        if len(ops) == 2 and ops[0].type == image.x.X86_OP_REG:
            destination = canonical(ops[0].reg)
            value = None
            if i.mnemonic == "mov" and ops[1].type == image.x.X86_OP_REG:
                value = expressions.get(canonical(ops[1].reg))
            elif i.mnemonic == "lea" and ops[1].type == image.x.X86_OP_MEM:
                memory = ops[1].mem
                base = expressions.get(canonical(memory.base)) if memory.base else (0, 0)
                index = expressions.get(canonical(memory.index)) if memory.index else (0, 0)
                if base is not None and index is not None:
                    value = (base[0] + index[0] * memory.scale,
                             base[1] + index[1] * memory.scale + memory.disp)
            elif i.mnemonic in ("add", "sub"):
                left = expressions.get(destination)
                right = (expressions.get(canonical(ops[1].reg))
                         if ops[1].type == image.x.X86_OP_REG else
                         (0, ops[1].imm) if ops[1].type == image.x.X86_OP_IMM else None)
                if left is not None and right is not None:
                    sign = 1 if i.mnemonic == "add" else -1
                    value = (left[0] + sign * right[0], left[1] + sign * right[1])
            elif i.mnemonic == "shl" and ops[1].type == image.x.X86_OP_IMM:
                left = expressions.get(destination)
                if left is not None and 0 <= ops[1].imm <= 8:
                    scale = 1 << ops[1].imm
                    value = (left[0] * scale, left[1] * scale)
            if value is not None and ops[0].size in (4, 8):
                updated[destination] = value
        if i.mnemonic == "call":
            raise DiscoveryError("GPU 索引循环包含未处理调用，不能证明表访问关系。")
        if i.mnemonic.startswith("j"):
            if ops[0].type != image.x.X86_OP_IMM:
                raise DiscoveryError("GPU 索引循环包含未处理间接跳转。")
            pending.append((ops[0].imm, updated))
            if i.mnemonic == "jmp":
                continue
        if i.mnemonic not in ("ret", "retf", "int3", "ud2"):
            pending.append((i.address + i.size, updated))
    ptr, stride, ptr_site = one(sorted(ptrs), "GPU entry 指针与步长")
    gpuid, id_stride, id_site = one(sorted(ids), "GPU ID 与步长")
    if stride != id_stride or not 8 <= stride <= 0x100:
        raise DiscoveryError("GPU 指针表与 ID 表步长不一致。")
    evidence.append({
        "rule": "gpu-registry-affine-index",
        "count_load": count_load.address, "pointer_load": ptr_site, "id_compare": id_site,
        "loop_start": loop_start, "loop_end": loop_end, "counter_register": counter,
        "max_count_policy": "32 是本后端处理容量上限，不声称是 NVIDIA 所有版本的最大值。",
    })
    return {
        "OFF_TABLE_COUNT": count_load.operands[1].mem.disp,
        "OFF_TABLE_ENTRY_PTR": ptr, "OFF_TABLE_ENTRY_GPUID": gpuid,
        "GPU_ENTRY_STRIDE": stride, "GPU_COUNT_MAX": 32,
    }


def discover(pe, result):
    evidence = []
    image = Image(pe)
    layout = root_layout(image, result, evidence)
    source_layout = {}
    board = board_method(image, layout, evidence, source_layout)
    layout.update(gpu_table_layout(image, result, evidence))
    if set(layout) != set(signatures.HYP):
        raise DiscoveryError("未推导全部后端对象布局字段。")
    return {
        "layout": layout, "board_set": board, "source_layout": source_layout, "evidence": evidence,
        "unresolved": [
            "selector 全部模式语义；secondary 未推导，状态返回未知而不读取旧偏移",
            "AUX28/AUX2C 仅保留状态 ABI 字段，返回未知而不读取推测地址",
            "原生 F7 全分支语义与后端状态机一致性",
            "NVIDIA 对象生命周期与并发调用契约",
        ],
    }
