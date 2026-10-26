"""按字段读写关系寻找 setter，避免绑定固定栈序言。"""

import re

import signatures
from discover import DiscoveryError, Image, one, gpu_table_layout


def register_family(image, reg):
    name = image.md.reg_name(reg) or ""
    if name.startswith("e"):
        return "r" + name[1:]
    if name in ("al", "ah", "ax"):
        return "rax"
    if name in ("cl", "ch", "cx"):
        return "rcx"
    if name in ("dl", "dh", "dx"):
        return "rdx"
    if name in ("bl", "bh", "bx"):
        return "rbx"
    if name in ("sil", "si"):
        return "rsi"
    if name in ("dil", "di"):
        return "rdi"
    if name.startswith("r") and name[-1:] in ("d", "w", "b"):
        return name[:-1]
    return name


def setter_facts(image, address):
    code = image.function(address)
    roots = {}
    by_address = {i.address: i for i in code}
    pending = [(code[0].address, {"rcx": "major", "rdx": "input"})]
    visited = set()
    while pending:
        address, state = pending.pop()
        token = (address, tuple(sorted(state.items())))
        if token in visited:
            continue
        visited.add(token)
        if len(visited) > 10000:
            raise DiscoveryError("setter 数据流状态过多。")
        i = by_address.get(address)
        if i is None:
            continue
        op = i.operands
        for position, operand in enumerate(op):
            if operand.type != image.x.X86_OP_MEM or operand.mem.index:
                continue
            origin = state.get(register_family(image, operand.mem.base))
            if not isinstance(origin, tuple) or origin[0] != "root":
                continue
            facts = roots[origin[1]]
            if (i.mnemonic == "cmp" and position == 0 and len(op) == 2 and operand.size == 1
                    and op[1].type == image.x.X86_OP_IMM and op[1].imm == 0):
                facts["init"].add((i.address, operand.mem.disp))
            if i.mnemonic == "mov" and len(op) == 2:
                if position == 0:
                    facts["writes"].add((i.address, operand.mem.disp, operand.size))
                    if op[1].type == image.x.X86_OP_REG and state.get(register_family(image, op[1].reg)) == "input":
                        facts["stores"].add((i.address, operand.mem.disp, operand.size))
                    if operand.size == 1 and op[1].type == image.x.X86_OP_IMM and op[1].imm == 1:
                        facts["flags"].add((i.address, operand.mem.disp))
                elif position == 1:
                    facts["reads"].add((i.address, operand.mem.disp, operand.size))
        new_state = dict(state)
        _, written = i.regs_access()
        for reg in written:
            new_state.pop(register_family(image, reg), None)
        if i.mnemonic == "mov" and len(op) == 2 and op[0].type == image.x.X86_OP_REG:
            value = None
            if op[1].type == image.x.X86_OP_REG:
                value = state.get(register_family(image, op[1].reg))
                pointer = value == "major" or isinstance(value, tuple) and value[0] == "root"
                if pointer and (op[0].size != 8 or op[1].size != 8):
                    value = None
            elif (op[0].size == 8 and image.mem(op[1], size=8) and not op[1].mem.index
                  and state.get(register_family(image, op[1].mem.base)) == "major"
                  and 0x100 <= op[1].mem.disp < 0x10000):
                root_offset = op[1].mem.disp
                roots.setdefault(root_offset, {
                    "init": set(), "stores": set(), "flags": set(), "reads": set(), "writes": set(),
                })
                value = ("root", root_offset)
            if value:
                new_state[register_family(image, op[0].reg)] = value
        if i.mnemonic == "call":
            for reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                new_state.pop(reg, None)
        if i.mnemonic in ("ret", "int3", "ud2"):
            continue
        if i.mnemonic.startswith("j"):
            if op[0].type == image.x.X86_OP_IMM:
                pending.append((op[0].imm, new_state))
            if i.mnemonic == "jmp":
                continue
        pending.append((i.address + i.size, new_state))
    candidates = []
    for root_offset, facts in roots.items():
        if len(facts["init"]) != 1 or not facts["stores"]:
            continue
        # 不同 Major 子对象分开建模，不能把一个对象的检查拼到另一个对象的写入。
        overwritten = False
        for _, offset, width in facts["stores"] | {(a, b, 1) for a, b in facts["flags"]}:
            matching = {a for a, b, size in facts["writes"]
                        if offset < b + size and b < offset + width}
            if len(matching) != 1:
                overwritten = True
                break
        if overwritten:
            continue
        candidates.append({
            "entry": code[0].address, "root": root_offset,
            "init": next(iter(facts["init"])), "stores": sorted(facts["stores"]),
            "flags": sorted(facts["flags"]), "reads": sorted(facts["reads"]),
        })
    return one(candidates, "由入口 Major 来源及初始化/参数写入确认的 Root")


def find_setters(image):
    candidates = set()
    # 覆盖 disp32 对象加载的基址寄存器变化；真正的 Major 来源由数据流判定。
    pattern = re.compile(b"[\x48\x49\x4c\x4d]\x8b[\x80-\xbf]", re.DOTALL)
    for section in image.pe.exec_sections():
        raw = image.pe.data[section["raw_ptr"]:section["raw_ptr"] + section["raw_size"]]
        for hit in pattern.finditer(raw):
            site = section["va"] + hit.start()
            try:
                start, end = image.containing(site)
                owner = image.owners[start]
                # 当前 setter 应为小函数；过大函数留给其他规则，不能靠邻近选取。
                if sum(b - a for a, b, _ in image.groups[owner]) <= 0x200:
                    candidates.add(owner)
            except DiscoveryError:
                continue
    amounts, eligibilities = [], []
    for entry in sorted(candidates):
        try:
            facts = setter_facts(image, entry)
        except DiscoveryError:
            continue
        words = [s for s in facts["stores"] if s[2] == 4]
        bytes_ = [s for s in facts["stores"] if s[2] == 1]
        if len(words) == 1 and len(facts["flags"]) == 1 and not bytes_:
            amounts.append(facts)
        if len(bytes_) == 1 and not words and not facts["flags"]:
            eligibilities.append(facts)
    pairs = []
    for eligibility in eligibilities:
        try:
            record, record_bytes = find_f7_record(image, eligibility)
        except DiscoveryError:
            continue
        for amount in amounts:
            if (amount["entry"] == eligibility["entry"]
                    or amount["root"] != eligibility["root"]
                    or amount["init"][1] != eligibility["init"][1]):
                continue
            try:
                find_upper_read(image, amount, eligibility, record, len(record_bytes))
            except DiscoveryError:
                continue
            pairs.append((amount, eligibility))
    return one(pairs, "共同 Root/init、F7 调用及边界运算关联的 setter 对")


def find_f7_record(image, elig, with_submit=False):
    """在原生生成器中识别三条 selector/source 记录，而非固定栈偏移字节。"""
    candidates = []
    for destination in image.callee_entries(image.function(elig["entry"])):
        try:
            owner = image.owners[image.containing(destination)[0]]
            if owner != destination:
                continue
            code = image.function(destination)
        except DiscoveryError:
            continue
        for index, instruction in enumerate(code):
            ops = instruction.operands
            if (instruction.mnemonic != "mov" or len(ops) != 2
                    or not image.mem(ops[0], "rsp", 2) or ops[0].mem.index
                    or ops[1].type != image.x.X86_OP_IMM or ops[1].imm != 0x3F7):
                continue
            slot = ops[0].mem.disp
            # 记录槽必须与当前值写入、相邻 FE 记录以及提交参数关联。
            preceding = []
            next_address = instruction.address
            for previous in reversed(code[max(0, index - 16):index]):
                if (previous.address + previous.size != next_address
                        or previous.mnemonic.startswith("j")
                        or previous.mnemonic in ("call", "ret", "int3", "ud2")):
                    break
                preceding.insert(0, previous)
                next_address = previous.address
            following = []
            next_address = instruction.address + instruction.size
            for following_instruction in code[index + 1:index + 10]:
                if (following_instruction.address != next_address
                        or following_instruction.mnemonic.startswith("j")
                        or following_instruction.mnemonic in ("ret", "int3", "ud2")):
                    break
                following.append(following_instruction)
                next_address += following_instruction.size
                if following_instruction.mnemonic == "call":
                    break
            records = {
                i.operands[0].mem.disp: i.operands[1].imm
                for i in preceding + following
                if i.mnemonic == "mov" and len(i.operands) == 2
                and image.mem(i.operands[0], "rsp", 2)
                and not i.operands[0].mem.index
                and i.operands[1].type == image.x.X86_OP_IMM
            }
            values = [
                i for i in following if i.mnemonic == "mov" and len(i.operands) == 2
                and image.mem(i.operands[0], "rsp", 4)
                and i.operands[0].mem.disp == slot + 4
                and i.operands[1].type == image.x.X86_OP_REG
            ]
            buffer_arg = [
                i for i in preceding if i.mnemonic == "lea" and len(i.operands) == 2
                and i.operands[0].reg == image.reg("r8")
                and image.mem(i.operands[1], "rsp")
                and i.operands[1].mem.disp == slot - 8
            ]
            count_args = [
                i.mnemonic == "mov" and len(i.operands) == 2
                and i.operands[0].type == image.x.X86_OP_REG
                and i.operands[0].reg == image.reg("r9d")
                and i.operands[1].type == image.x.X86_OP_IMM and i.operands[1].imm == 3
                for i in preceding
            ]
            count_arg = any(count_args)
            last_writers = {}
            for operation in preceding + [instruction] + following:
                if operation.mnemonic == "call":
                    break
                _, writes = operation.regs_access()
                for reg in writes:
                    last_writers[register_family(image, reg)] = operation
            if buffer_arg and last_writers.get("r8") is not buffer_arg[0]:
                continue
            count_writer = last_writers.get("r9")
            if not count_writer or count_writer not in preceding:
                continue
            count_arg = count_arg and (
                count_writer.mnemonic == "mov" and len(count_writer.operands) == 2
                and count_writer.operands[1].type == image.x.X86_OP_IMM
                and count_writer.operands[1].imm == 3
            )
            if any(image.reg("rsp") in i.regs_access()[1]
                   for i in preceding + [instruction] + following if i.mnemonic != "call"):
                continue
            if (records.get(slot - 8) == 0x3FE and records.get(slot + 8) == 0x6FE
                    and len(values) == 1 and len(buffer_arg) == 1 and count_arg
                    and image.direct_calls(following)):
                submit = following[-1]
                try:
                    updater, _ = image.resolve_direct_entry(submit.operands[0].imm)
                except DiscoveryError:
                    continue
                candidates.append((instruction.address, bytes(instruction.bytes),
                                   submit.address, updater))
    selected = one(candidates, "Eligibility 调用链中的 F7 记录及提交参数")
    return selected if with_submit else selected[:2]


def find_gpu_registry(image, evidence=None):
    """粗筛 RIP 对象加载，再用表计数、ID 比较和指针索引证明用途。"""
    pattern = re.compile(b"[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", re.DOTALL)
    candidates = []
    for section in image.pe.exec_sections():
        raw = image.pe.data[section["raw_ptr"]:section["raw_ptr"] + section["raw_size"]]
        for match in pattern.finditer(raw):
            start = section["va"] + match.start()
            window = raw[match.start():match.start() + 40]
            code = list(image.md.disasm(window, start))
            if not code:
                continue
            first = code[0]
            loaded_reg = first.operands[0].reg
            global_rva = first.address + first.size + first.operands[1].mem.disp
            global_section = image.pe.containing_section(global_rva)
            if global_section is None or global_section["executable"]:
                continue
            for instruction in code[1:]:
                ops = instruction.operands
                if instruction.mnemonic in ("ret", "call") or instruction.mnemonic.startswith("j"):
                    break
                if (instruction.mnemonic == "mov" and len(ops) == 2
                        and ops[0].type == image.x.X86_OP_REG and ops[0].size == 8
                        and image.mem(ops[1], size=8) and ops[1].mem.base == loaded_reg
                        and not ops[1].mem.index and 0 < ops[1].mem.disp < 0x10000):
                    derived = {
                        "RVA_GPU_REGISTRY_FN": start, "RVA_GPU_GLOBAL": global_rva,
                        "OFF_GLOBAL_GPU_TABLE": ops[1].mem.disp,
                        "_sig_gpu_registry": image.read(start, instruction.address + instruction.size - start).hex(),
                    }
                    try:
                        layout = gpu_table_layout(image, {"derived": derived}, [])
                    except DiscoveryError:
                        break
                    candidates.append((derived, layout))
                    break
                _, writes = instruction.regs_access()
                if any(register_family(image, r) == register_family(image, loaded_reg) for r in writes):
                    break
    groups = {}
    for derived, layout in candidates:
        # 多个访问函数可以指向同一张表；入口和精确指令字节不属于表身份。
        identity = (
            derived["RVA_GPU_GLOBAL"], derived["OFF_GLOBAL_GPU_TABLE"],
            tuple(sorted(layout.items())),
        )
        groups.setdefault(identity, []).append((derived, layout))
    if not groups:
        raise DiscoveryError("GPU registry：没有找到可推导完整表布局的访问函数。")
    if len(groups) != 1:
        summaries = [
            {
                "global_rva": identity[0], "table_offset": identity[1],
                "layout": dict(identity[2]),
                "entries": sorted({d["RVA_GPU_REGISTRY_FN"] for d, _ in members}),
            }
            for identity, members in sorted(groups.items())
        ]
        raise DiscoveryError(
            "GPU registry：发现 {} 组冲突的全局对象或表布局，拒绝合并：{}".format(
                len(groups), summaries
            )
        )
    members = next(iter(groups.values()))
    # 后端不会调用这个入口，仅用它的字节作运行期校验锚点。
    # 在表身份一致后用短签名、RVA 排序，保证选择可重复而非猜测唯一函数。
    chosen, layout = min(
        members,
        key=lambda pair: (
            len(bytes.fromhex(pair[0]["_sig_gpu_registry"])),
            pair[0]["RVA_GPU_REGISTRY_FN"],
        ),
    )
    if evidence is not None:
        evidence.update({
            "rule": "gpu-registry-equivalent-accessors",
            "global_rva": chosen["RVA_GPU_GLOBAL"],
            "table_offset": chosen["OFF_GLOBAL_GPU_TABLE"],
            "layout": layout,
            "accessor_entries": sorted({d["RVA_GPU_REGISTRY_FN"] for d, _ in members}),
            "selected_validation_anchor": chosen["RVA_GPU_REGISTRY_FN"],
            "selection": "布局一致后按精确签名长度、RVA 排序；入口不被内核调用。",
        })
    return chosen


def find_upper_read(image, amount, elig, record, record_size=7):
    """沿 Eligibility 调用找到生成器，识别两个边界读取后的无符号比较。"""
    from discover import root_lookup_from_generator
    generator = image.generator_for_record(image.function(elig["entry"]), record)
    code = image.function(generator)
    contract = root_lookup_from_generator(image, generator, amount["root"])
    root_reads = set(tuple(read) for read in contract["root_reads"])
    limits = {offset for _, offset, width in amount["reads"] if width == 4}
    candidates = []
    for index, comparison in enumerate(code):
        if comparison.mnemonic != "cmp" or len(comparison.operands) != 2:
            continue
        if any(op.type != image.x.X86_OP_REG or op.size != 4 for op in comparison.operands):
            continue
        if index + 1 >= len(code) or code[index + 1].mnemonic not in ("jbe", "ja"):
            continue
        # 两个比较操作数的最近定义必须是从同一个 Root 读取的边界字段。
        definitions = []
        for operand in comparison.operands:
            family = register_family(image, operand.reg)
            definition = None
            for previous in reversed(code[:index]):
                if previous.mnemonic == "call" or previous.mnemonic.startswith("j"):
                    break
                _, writes = previous.regs_access()
                if not any(register_family(image, r) == family for r in writes):
                    continue
                if (previous.mnemonic == "mov" and len(previous.operands) == 2
                        and previous.operands[0].size == 4
                        and image.mem(previous.operands[1], size=4)
                        and (previous.address, previous.operands[1].mem.disp, 4) in root_reads
                        and not previous.operands[1].mem.index
                        and previous.operands[1].mem.disp in limits):
                    definition = previous
                break
            definitions.append(definition)
        if None in definitions:
            continue
        first, second = definitions
        if first.operands[1].mem.disp == second.operands[1].mem.disp:
            continue
        # 只支持 upper <= lower 跳到饱和分支，或其反向条件。
        # 两字段角色还必须由后续 upper-lower 减法交叉验证。
        upper_family = register_family(image, comparison.operands[0].reg)
        lower_family = register_family(image, comparison.operands[1].reg)
        following = code[index + 2:index + 7]
        subtraction = False
        upper_aliases = {upper_family}
        lower_aliases = {lower_family}
        for instruction in following:
            ops = instruction.operands
            if instruction.mnemonic == "call" or instruction.mnemonic.startswith("j") or instruction.mnemonic in (
                    "ret", "retf", "int3", "ud2"):
                break
            _, written = instruction.regs_access()
            copied = (instruction.mnemonic == "mov" and len(ops) == 2
                      and all(o.type == image.x.X86_OP_REG for o in ops)
                      and all(o.size == 4 for o in ops))
            prior_upper, prior_lower = set(upper_aliases), set(lower_aliases)
            writes = {register_family(image, r) for r in written}
            upper_aliases.difference_update(writes)
            lower_aliases.difference_update(writes)
            if copied:
                destination = register_family(image, ops[0].reg)
                source = register_family(image, ops[1].reg)
                if source in prior_upper:
                    upper_aliases.add(destination)
                if source in prior_lower:
                    lower_aliases.add(destination)
            if (instruction.mnemonic == "sub" and len(ops) == 2
                    and all(o.type == image.x.X86_OP_REG and o.size == 4 for o in ops)
                    and register_family(image, ops[0].reg) in prior_upper
                    and register_family(image, ops[1].reg) in prior_lower):
                subtraction = True
        if subtraction:
            candidates.append((first.address, bytes(first.bytes), first.operands[1].mem.disp,
                               second.operands[1].mem.disp))
    return one(candidates, "F7 上下界比较与差值运算")


def seed(pe):
    image = Image(pe)
    amount, elig = find_setters(image)
    # 保留独立的 registry 和 F7 锚点检查，不能因 setter 已识别就跳过它们。
    gpu_evidence = {}
    gpu = find_gpu_registry(image, gpu_evidence)
    f7_rva, f7_bytes = find_f7_record(image, elig)
    major, init = amount["root"], amount["init"][1]
    upper_rva, upper_bytes, upper, lower = find_upper_read(image, amount, elig, f7_rva, len(f7_bytes))
    derived = {
        **gpu,
        "RVA_SET_AMOUNT": amount["entry"], "RVA_SET_ELIG": elig["entry"],
        "OFF_MAJOR_POWER_ROOT": major, "OFF_ROOT_INIT": init,
        "_sig_set_amount": image.read(amount["entry"], 21).hex(),
        "_sig_set_elig": image.read(elig["entry"], 18).hex(),
        "RVA_F7_RECORD": f7_rva, "_sig_f7_record": f7_bytes.hex(),
        "RVA_F7_UPPER_LOAD": upper_rva, "_sig_upper_load": upper_bytes.hex(),
        "OFF_ROOT_UPPER": upper,
        "OFF_ROOT_ELIG": elig["stores"][0][1],
        "OFF_ROOT_AMOUNT": amount["stores"][0][1],
        "OFF_ROOT_AMOUNT_ACTIVE": amount["flags"][0][1],
    }
    for name, delta in (("POLICY_KEY", 12), ("LOWER", 16)):
        derived["OFF_ROOT_" + name] = init + delta
    derived["OFF_ROOT_LOWER"] = lower
    return {
        "pe_identity": {
            "machine": "0x%04X" % pe.machine,
            "time_date_stamp": "0x%08X" % pe.timestamp,
            "size_of_image": "0x%08X" % pe.size_of_image,
        },
        "derived": derived, "hypothesis": {}, "board_set": None,
        "anchor_evidence": {
            "rule": "setter-read-write", "amount": amount, "eligibility": elig,
            "gpu_registry": gpu_evidence,
        },
    }
