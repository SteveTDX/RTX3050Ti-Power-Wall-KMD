"""检查构建所需的反汇编依赖，不分析驱动或运行产物。"""

import sys


def main():
    quiet = "--quiet" in sys.argv[1:]
    try:
        import capstone
        if capstone.__version__ != "5.0.6":
            raise RuntimeError("需要 Capstone 5.0.6，当前为 " + str(capstone.__version__))
        # 导入成功不一定意味着原生动态库可加载。
        capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    except Exception as error:
        if not quiet:
            print("Capstone 依赖检查失败：{}：{}".format(type(error).__name__, error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
