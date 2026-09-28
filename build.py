#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kittyscan 1.0 (based on fscan 1.8.4) Multi-Platform Builder
modified by laxy
编译完成后可选 UPX 压缩，减小二进制体积 80%+
支持 garble 混淆编译，绕过杀毒软件检测
"""

import os
import subprocess
import time
import shutil
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent.absolute()
OUTPUT_DIR = SCRIPT_DIR / "output"
TOOLS_DIR = SCRIPT_DIR / "tools"

# 平台定义：(goos, goarch, output_name, description)
PLATFORMS = {
    "1": ("windows", "386",    "kittyscan_win32.exe",      "Windows x86 (32-bit)"),
    "2": ("windows", "amd64",  "kittyscan_win64.exe",      "Windows x64 (64-bit)"),
    "3": ("windows", "arm64",  "kittyscan_win_arm64.exe",  "Windows ARM64"),
    "4": ("linux",   "386",    "kittyscan_linux32",        "Linux x86 (32-bit)"),
    "5": ("linux",   "amd64",  "kittyscan_linux64",        "Linux x64 (64-bit)"),
    "6": ("linux",   "arm64",  "kittyscan_linux_arm64",    "Linux ARM64"),
}

ALL_KEYS = ["1", "2", "3", "4", "5", "6"]


def find_garble():
    """查找 garble 是否安装"""
    garble_path = shutil.which("garble")
    if garble_path:
        return True
    return False


def install_garble():
    """安装 garble"""
    print("  [garble] 正在安装...")
    result = subprocess.run(
        ["go", "install", "mvdan.cc/garble@latest"],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode == 0:
        print("  [garble] 安装成功")
        return True
    else:
        print(f"  [garble] 安装失败: {result.stderr[:200]}")
        return False


def find_upx():
    """查找 UPX 可执行文件（优先选最新版）"""
    upx_in_path = shutil.which("upx")
    if upx_in_path:
        return Path(upx_in_path)
    candidates = []
    for pattern in ("upx.exe", "upx"):
        for p in TOOLS_DIR.rglob(pattern):
            candidates.append(p)
    if not candidates:
        return None
    import re
    def version_key(p):
        nums = re.findall(r"(\d+)", str(p.parent.name))
        return [int(n) for n in nums] if nums else [0]
    candidates.sort(key=version_key, reverse=True)
    return candidates[0]


def upx_compress(exe_path, upx_path):
    """使用 UPX 压缩二进制文件，返回是否成功"""
    if not upx_path or not exe_path.exists():
        return False
    original_size = exe_path.stat().st_size
    print(f"\n  [UPX] 正在压缩 {exe_path.name}...")
    result = subprocess.run(
        [str(upx_path), "--best", "--lzma", str(exe_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode == 0 and exe_path.exists():
        new_size = exe_path.stat().st_size
        saved = original_size - new_size
        pct = saved / original_size * 100 if original_size else 0
        print(f"  [UPX] {fmt_size(original_size)} -> {fmt_size(new_size)} (节省 {pct:.1f}%)")
        return True
    else:
        print(f"  [UPX] 压缩失败: {result.stderr[:200]}")
        return False


def prompt_upx(exe_files, upx_path):
    """编译完成后询问用户是否使用 UPX 压缩"""
    if not upx_path:
        print("\n  [UPX] 未找到 UPX，跳过压缩")
        print("  提示: 将 upx.exe 放入 tools/ 目录或添加到 PATH 即可启用")
        return

    print("\n  ============================================")
    print("  编译完成！是否使用 UPX 压缩？")
    print("  ============================================")
    print(f"  [1] 完成编译（不压缩）")
    print(f"  [2] 使用 UPX 压缩（减小体积 ~80%）")
    print()

    choice = input("  请选择 [1/2]: ").strip()
    if choice == "2":
        ok = 0
        for f in exe_files:
            if upx_compress(f, upx_path):
                ok += 1
        print(f"\n  [UPX] 压缩完成: {ok}/{len(exe_files)} 个文件")
    else:
        print("\n  跳过 UPX 压缩")


def fmt_size(n):
    """格式化文件大小"""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / (1024 * 1024):.2f} MB"


def show_menu():
    """显示构建菜单"""
    print()
    print("  ============================================")
    print("         Kittyscan 1.0 Multi-Platform Builder")
    print("                 modified by laxy")
    print("  ============================================")
    print()
    print("  [0] Build ALL platforms")
    print()
    print("  --- Windows ---")
    print("  [1] Windows x86 (32-bit)    - Win7/Server2008+")
    print("  [2] Windows x64 (64-bit)    - Win10/Server2016+")
    print("  [3] Windows ARM64           - ARM devices")
    print()
    print("  --- Linux ---")
    print("  [4] Linux x86 (32-bit)      - Legacy systems")
    print("  [5] Linux x64 (64-bit)      - Modern systems")
    print("  [6] Linux ARM64             - ARM servers/devices")
    print()
    print("  [7] Exit")
    print()
    print("  ============================================")
    print()


def prompt_build_mode():
    """询问编译模式（普通/混淆）"""
    print()
    print("  ============================================")
    print("  选择编译模式")
    print("  ============================================")
    print("  [1] 普通编译（标准 Go 编译）")
    print("  [2] 混淆编译（garble 混淆，绕过杀毒）")
    print()

    choice = input("  请选择 [1/2]: ").strip()
    return choice == "2"


def prompt_obfuscate_options():
    """询问混淆选项"""
    print()
    print("  ============================================")
    print("  混淆选项")
    print("  ============================================")
    print("  [1] 标准混淆（推荐）")
    print("  [2] 字面量混淆（更安全，编译稍慢）")
    print("  [3] Tiny模式（最激进，二进制最小）")
    print()

    choice = input("  请选择 [1/2/3]: ").strip()

    literals = choice in ["2", "3"]
    tiny = choice == "3"

    return literals, tiny


def do_build(goos, goarch, output_name, platform_desc, use_garble=False, literals=False, tiny=False):
    """执行单个平台的编译，返回输出文件 Path 或 None"""
    print()
    print(f"  [Building] {platform_desc} ({goos}/{goarch})...")
    if use_garble:
        print(f"  [Mode] 混淆编译 (literals={literals}, tiny={tiny})")
    print("  --------------------------------------------")

    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    env["CGO_ENABLED"] = "0"
    env["GOTOOLCHAIN"] = "local"

    # 构建命令
    if use_garble:
        cmd = ["garble"]
        if literals:
            cmd.append("-literals")
        if tiny:
            cmd.append("-tiny")
        cmd.extend([
            "build",
            "-ldflags=-s -w",
            "-trimpath",
            "-o", str(OUTPUT_DIR / output_name),
            "main.go",
        ])
    else:
        cmd = [
            "go", "build",
            "-ldflags=-s -w",
            "-trimpath",
            "-o", str(OUTPUT_DIR / output_name),
            "main.go",
        ]

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        elapsed = time.time() - start

        if result.returncode != 0:
            print(f"  [FAIL] 编译失败! (耗时 {elapsed:.1f}s)")
            if result.stderr:
                print(f"  Error: {result.stderr[:300]}")
            return None

        exe_path = OUTPUT_DIR / output_name
        if not exe_path.exists():
            print(f"  [FAIL] 输出文件未找到: {output_name}")
            return None

        size = exe_path.stat().st_size
        print(f"  [OK] {fmt_size(size)} | 耗时 {elapsed:.1f}s -> {exe_path.name}")
        return exe_path

    except FileNotFoundError:
        if use_garble:
            print("  [ERROR] 未找到 garble，请先安装: go install mvdan.cc/garble@latest")
        else:
            print("  [ERROR] 未找到 Go，请安装 Go 并添加到 PATH")
        return None
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


def build_all(upx_path, use_garble=False, literals=False, tiny=False):
    """编译全部平台"""

    ok = 0
    built_files = []
    total_start = time.time()

    for k in ALL_KEYS:
        goos, goarch, name, desc = PLATFORMS[k]
        exe = do_build(goos, goarch, name, desc, use_garble, literals, tiny)
        if exe:
            ok += 1
            built_files.append(exe)

    total_elapsed = time.time() - total_start

    print()
    print("  ============================================")
    if ok == len(ALL_KEYS):
        print(f"  [OK] 全部 {len(ALL_KEYS)} 个平台编译成功!")
    else:
        print(f"  [PARTIAL] {ok}/{len(ALL_KEYS)} 个平台编译成功")
    print(f"  [TIME] 总耗时 {total_elapsed:.1f}s")
    if use_garble:
        print(f"  [Mode] 混淆编译 (literals={literals}, tiny={tiny})")
    print("  ============================================")

    # 输出文件汇总
    if built_files:
        print("\n  输出文件:")
        for f in built_files:
            print(f"    {f.name:<35} {fmt_size(f.stat().st_size)}")

    # 询问是否 UPX 压缩
    if built_files:
        prompt_upx(built_files, upx_path)


def build_single(key, upx_path, use_garble=False, literals=False, tiny=False):
    """编译单个平台"""
    goos, goarch, name, desc = PLATFORMS[key]
    exe = do_build(goos, goarch, name, desc, use_garble, literals, tiny)

    if exe:
        prompt_upx([exe], upx_path)


def main():
    """主函数"""
    os.chdir(str(SCRIPT_DIR))
    OUTPUT_DIR.mkdir(exist_ok=True)

    # 查找 UPX（仅记录，不自动使用）
    upx_path = find_upx()
    if upx_path:
        print(f"  [UPX] 已检测到: {upx_path}")
    else:
        print("  [UPX] 未检测到（编译后可选择是否压缩）")

    # 检查 garble
    has_garble = find_garble()
    if has_garble:
        print(f"  [garble] 已检测到")
    else:
        print("  [garble] 未检测到（如需混淆编译，会自动安装）")

    # 先选择编译模式
    use_garble = prompt_build_mode()

    # 如果选择混淆编译，检查 garble 是否安装
    if use_garble and not has_garble:
        if not install_garble():
            print("  [!] garble 安装失败，将使用普通编译")
            use_garble = False

    # 混淆选项
    literals = False
    tiny = False
    if use_garble:
        literals, tiny = prompt_obfuscate_options()

    while True:
        show_menu()
        choice = input("  选择 [0-7]: ").strip()

        if choice == "0":
            build_all(upx_path, use_garble, literals, tiny)
            print()
        elif choice in PLATFORMS:
            build_single(choice, upx_path, use_garble, literals, tiny)
            print("\n  按回车退出...")
            input()
            break
        elif choice == "7":
            print("\n  再见!")
            break
        else:
            print("  [!] 无效选项")
            time.sleep(1)


if __name__ == "__main__":
    main()