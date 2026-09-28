#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kittyscan POC Validator
批量校验 WebScan/pocs/*.yml 的逻辑错误和常见问题
"""

import os
import sys
import yaml
import re
import io
from pathlib import Path
from collections import defaultdict

# 修复 Windows 终端编码问题
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

POC_DIR = Path(__file__).parent

# CEL 表达式中可用的内置函数
CEL_FUNCTIONS = {
    "bcontains", "bmatches", "md5", "randomInt", "randomLowercase",
    "randomUppercase", "randomString", "base64", "base64Decode",
    "urlencode", "urldecode", "substr", "wait", "icontains",
    "TDdate", "shirokey", "startsWith", "istartsWith", "hexdecode",
    "newReverse",
}

# CEL 中可用的变量
CEL_VARIABLES = {"request", "response", "reverse"}

# 常见 expression 中的错误模式
BAD_PATTERNS = [
    (r'response\.status\s*=\s*\d+[^=]', "单等号 = 是赋值，应使用 == 比较"),
    (r'&&\s*\|\|', "混合 && 和 || 可能有优先级问题，建议加括号"),
    (r'\|\|\s*&&', "混合 || 和 && 可能有优先级问题，建议加括号"),
    (r'response\.body\.bcontains\(["\']', "bcontains 参数应为 b'...' (bytes类型)，不是字符串"),
]


class Issue:
    """一个问题"""
    def __init__(self, filename, level, message, line_hint=""):
        self.filename = filename
        self.level = level  # ERROR, WARNING, INFO
        self.message = message
        self.line_hint = line_hint

    def __str__(self):
        prefix = {"ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}[self.level]
        loc = f" (line ~{self.line_hint})" if self.line_hint else ""
        return f"{prefix} [{self.level}] {self.filename}{loc}: {self.message}"


def load_poc(filepath):
    """加载并解析 YAML POC 文件"""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return None, str(e), content
    return data, None, content


def extract_set_vars(data):
    """提取 set 和 sets 中定义的变量名"""
    vars = set()
    # set 字段: StrMap (list of dicts with key/value)
    if "set" in data and data["set"]:
        s = data["set"]
        if isinstance(s, dict):
            vars.update(s.keys())
        elif isinstance(s, list):
            for item in s:
                if isinstance(item, dict) and "key" in item:
                    vars.add(item["key"])
    # sets 字段: ListMap
    if "sets" in data and data["sets"]:
        s = data["sets"]
        if isinstance(s, dict):
            vars.update(s.keys())
        elif isinstance(s, list):
            for item in s:
                if isinstance(item, dict) and "key" in item:
                    vars.add(item["key"])
    return vars


def check_expression_vars(expr, defined_vars, poc_name):
    """检查表达式中引用的变量是否已定义"""
    issues = []
    if not expr:
        return issues

    # 提取 {{var}} 模板变量
    template_vars = set(re.findall(r'\{\{(\w+)\}\}', expr))
    for v in template_vars:
        if v not in defined_vars and v not in CEL_VARIABLES:
            issues.append(Issue(poc_name, "WARNING",
                f"模板变量 '{v}' 在 set/sets 中未定义"))

    return issues


def check_expression_syntax(expr, poc_name):
    """检查 CEL 表达式语法问题"""
    issues = []
    if not expr:
        return issues

    for pattern, msg in BAD_PATTERNS:
        if re.search(pattern, expr):
            if msg:
                issues.append(Issue(poc_name, "WARNING", f"表达式问题: {msg}"))

    # 检查常见拼写错误
    typos = [
        (r'response\.statu\b(?!s)', "可能拼写错误: 'statu' 应为 'status'"),
        (r'response\.body\.bcontians', "拼写错误: 'bcontians' 应为 'bcontains'"),
        (r'response\.body\.bcontain\b(?!s)', "拼写错误: 'bcontain' 应为 'bcontains'"),
        (r'response\.header\b(?!s)', "可能拼写错误: 'header' 应为 'headers'"),
        (r'response\.content_type\.contians', "拼写错误: 'contians' 应为 'contains'"),
    ]
    for pattern, msg in typos:
        if re.search(pattern, expr, re.IGNORECASE):
            issues.append(Issue(poc_name, "ERROR", f"拼写错误: {msg}"))

    return issues


def check_rules(rules, defined_vars, poc_name):
    """检查 rules 列表"""
    issues = []
    if not rules:
        issues.append(Issue(poc_name, "ERROR", "rules 为空"))
        return issues
    if not isinstance(rules, list):
        issues.append(Issue(poc_name, "ERROR", "rules 应为列表"))
        return issues

    # 跟踪 search 字段提取的变量（后续 rule 可以使用）
    accumulated_vars = set(defined_vars)

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            issues.append(Issue(poc_name, "ERROR", f"rules[{i}] 应为字典"))
            continue

        # 检查 method
        method = rule.get("method", "")
        if not method:
            issues.append(Issue(poc_name, "WARNING", f"rules[{i}]: 缺少 method 字段"))
        elif method.upper() not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "MOVE"):
            issues.append(Issue(poc_name, "WARNING", f"rules[{i}]: method '{method}' 不常见"))

        # 检查 path
        path = rule.get("path", "")
        if not path:
            issues.append(Issue(poc_name, "WARNING", f"rules[{i}]: 缺少 path 字段"))

        # 检查 expression
        expr = rule.get("expression", "")
        if not expr:
            issues.append(Issue(poc_name, "WARNING", f"rules[{i}]: 缺少 expression（默认为 true，会始终匹配）"))

        # 检查表达式中的变量引用
        issues.extend(check_expression_vars(expr, accumulated_vars, poc_name))

        # 检查表达式语法
        issues.extend(check_expression_syntax(expr, poc_name))

        # 检查 path 中的模板变量
        if path:
            issues.extend(check_expression_vars(path, accumulated_vars, poc_name))

        # 检查 body 中的模板变量
        body = rule.get("body", "")
        if body:
            issues.extend(check_expression_vars(body, accumulated_vars, poc_name))

        # 检查 headers 中的模板变量
        headers = rule.get("headers", {})
        if headers and isinstance(headers, dict):
            for k, v in headers.items():
                if isinstance(v, str):
                    issues.extend(check_expression_vars(v, accumulated_vars, poc_name))

        # 如果有 search 字段，提取命名捕获组作为后续可用变量
        search = rule.get("search", "")
        if search:
            try:
                r = re.compile(search)
                for group_name in r.groupindex:
                    accumulated_vars.add(group_name)
            except re.error:
                issues.append(Issue(poc_name, "WARNING", f"rules[{i}]: search 正则表达式语法错误"))

    return issues


def check_logical_errors(data, content, poc_name):
    """检查逻辑错误"""
    issues = []
    rules = data.get("rules", [])
    groups = data.get("groups", {})

    # 检查未知顶层字段（可能的拼写错误）
    known_top_fields = {"name", "set", "sets", "rules", "groups", "detail", "manual", "transport", "info"}
    unknown_fields = set(data.keys()) - known_top_fields
    for f in unknown_fields:
        # 常见拼写错误
        if f == "group":
            continue  # 已在上面单独检查
        issues.append(Issue(poc_name, "WARNING", f"未知顶层字段 '{f}'，可能是拼写错误"))

    # 检查 200 状态码过度依赖
    if rules:
        all_check_200 = all(
            isinstance(r, dict) and "response.status == 200" in r.get("expression", "")
            for r in rules
            if isinstance(r, dict)
        )
        if all_check_200 and len(rules) > 1:
            issues.append(Issue(poc_name, "INFO",
                "所有 rule 都检查 status==200，某些中间步骤可能应允许其他状态码"))

    # 检查是否有 GET 请求带 body（虽然技术上可行，但不规范）
    for i, rule in enumerate(rules):
        if isinstance(rule, dict):
            method = rule.get("method", "").upper()
            body = rule.get("body", "")
            if method == "GET" and body:
                issues.append(Issue(poc_name, "WARNING",
                    f"rules[{i}]: GET 请求带有 body，大多数服务器会忽略"))

    # 检查 continue: true 但只有一个 rule 的情况
    if rules and len(rules) == 1:
        if isinstance(rules[0], dict) and rules[0].get("continue"):
            issues.append(Issue(poc_name, "WARNING",
                "只有一个 rule 但设置了 continue: true，这没有意义"))

    # 检查 name 格式
    name = data.get("name", "")
    if name and not name.startswith("poc-yaml-") and not name.startswith("poc-yaml-"):
        # 不强制要求，但建议统一
        pass

    # 检查是否有 groups 但没有 rules（或反之）
    if groups and rules:
        issues.append(Issue(poc_name, "WARNING",
            "同时定义了 rules 和 groups，通常只应使用其中一个"))

    return issues


def check_sets_logic(data, poc_name):
    """检查 sets（爆破模式）的逻辑"""
    issues = []
    sets = data.get("sets", {})
    rules = data.get("rules", [])

    if not sets:
        return issues

    # 检查 sets 是否被 rules 引用
    if isinstance(sets, dict):
        set_keys = set(sets.keys())
    elif isinstance(sets, list):
        set_keys = set()
        for item in sets:
            if isinstance(item, dict) and "key" in item:
                set_keys.add(item["key"])
    else:
        return issues

    # 检查 rules 中是否有引用 sets 变量的
    all_text = yaml.dump(rules)
    unused = set()
    for key in set_keys:
        placeholder = "{{" + key + "}}"
        if placeholder not in all_text:
            unused.add(key)

    # payload 通常不直接在 path/body 中使用，而是通过 shirokey() 等函数
    unused.discard("payload")

    if unused:
        issues.append(Issue(poc_name, "WARNING",
            f"sets 中定义了 {unused} 但未在 rules 的 path/body/headers 中引用"))

    return issues


def check_duplicate_values(data, poc_name):
    """检查 sets 中是否有重复值"""
    issues = []
    sets = data.get("sets", {})

    if isinstance(sets, dict):
        for key, values in sets.items():
            if isinstance(values, list) and len(values) > 1:
                seen = {}
                for i, v in enumerate(values):
                    if v in seen:
                        issues.append(Issue(poc_name, "INFO",
                            f"sets.{key} 有重复值: '{v}' (索引 {seen[v]} 和 {i})"))
                    else:
                        seen[v] = i

    return issues


def check_content_encoding(content, poc_name):
    """检查文件内容编码和格式问题"""
    issues = []

    # 检查 BOM
    if content.startswith('\ufeff'):
        issues.append(Issue(poc_name, "WARNING", "文件包含 UTF-8 BOM 头，可能导致解析问题"))

    # 检查 Tab 和空格混用
    lines = content.split('\n')
    has_tab = any('\t' in line for line in lines)
    has_space_indent = any(re.match(r'^ +', line) for line in lines)
    if has_tab and has_space_indent:
        issues.append(Issue(poc_name, "WARNING", "Tab 和空格混用缩进"))

    return issues


def check_expression_value_type(data, poc_name):
    """检查 expression 返回值类型相关问题"""
    issues = []
    rules = data.get("rules", [])
    sets = data.get("sets", {})

    # 如果有 sets（爆破模式），检查 payload 的定义
    if sets and isinstance(sets, dict):
        if "payload" in sets:
            payload_expr = sets["payload"]
            if isinstance(payload_expr, list):
                for expr in payload_expr:
                    if isinstance(expr, str) and "shirokey" in expr:
                        # shirokey 函数需要 key 和 mode 两个参数
                        pass  # 正常

    return issues


def validate_poc(filepath):
    """校验单个 POC 文件"""
    poc_name = filepath.name
    issues = []

    # 1. 加载 YAML
    data, error, content = load_poc(filepath)
    if error:
        issues.append(Issue(poc_name, "ERROR", f"YAML 解析失败: {error}"))
        return issues

    if not isinstance(data, dict):
        issues.append(Issue(poc_name, "ERROR", "YAML 根元素不是字典"))
        return issues

    # 2. 检查文件编码
    issues.extend(check_content_encoding(content, poc_name))

    # 3. 检查必需字段
    if "name" not in data:
        issues.append(Issue(poc_name, "ERROR", "缺少 name 字段"))

    has_rules = "rules" in data and data["rules"]
    has_groups = "groups" in data and data["groups"]

    if not has_rules and not has_groups:
        issues.append(Issue(poc_name, "ERROR", "缺少 rules 和 groups（至少需要一个）"))

    # 检查拼写错误: group (单数) vs groups (复数)
    if "group" in data and "groups" not in data:
        issues.append(Issue(poc_name, "ERROR",
            "使用了 'group'（单数），Go 解析器期望的是 'groups'（复数），此 POC 不会被执行"))

    # 4. 提取定义的变量
    defined_vars = extract_set_vars(data)
    defined_vars.update(CEL_VARIABLES)

    # 5. 检查 rules（如果存在）
    rules = data.get("rules", [])
    if has_rules:
        issues.extend(check_rules(rules, defined_vars, poc_name))

    # 6. 检查 groups（如果存在）
    groups = data.get("groups", {})
    if groups and isinstance(groups, dict):
        for group_name, group_rules in groups.items():
            if isinstance(group_rules, list):
                issues.extend(check_rules(group_rules, defined_vars, poc_name))

    # 7. 检查逻辑问题
    issues.extend(check_logical_errors(data, content, poc_name))

    # 8. 检查 sets
    issues.extend(check_sets_logic(data, poc_name))

    # 9. 检查重复值
    issues.extend(check_duplicate_values(data, poc_name))

    # 10. 检查 expression 值类型
    issues.extend(check_expression_value_type(data, poc_name))

    return issues


def main():
    """主函数"""
    poc_files = sorted(POC_DIR.glob("*.yml"))

    # 排除自身
    poc_files = [f for f in poc_files if f.name != "validate_pocs.py"]

    print(f"\n  Kittyscan POC Validator")
    print(f"  扫描目录: {POC_DIR}")
    print(f"  POC 总数: {len(poc_files)}")
    print(f"  {'='*60}\n")

    all_issues = []
    error_count = 0
    warning_count = 0
    info_count = 0
    clean_count = 0
    error_files = []

    for filepath in poc_files:
        issues = validate_poc(filepath)
        if issues:
            all_issues.extend(issues)
            for issue in issues:
                if issue.level == "ERROR":
                    error_count += 1
                elif issue.level == "WARNING":
                    warning_count += 1
                else:
                    info_count += 1
            error_files.append((filepath.name, issues))
        else:
            clean_count += 1

    # 按文件分组输出
    print(f"  {'='*60}")
    print(f"  扫描结果汇总")
    print(f"  {'='*60}")
    print(f"  ✅ 无问题: {clean_count} 个 POC")
    print(f"  ❌ ERROR:  {error_count} 个")
    print(f"  ⚠️ WARNING: {warning_count} 个")
    print(f"  ℹ️ INFO:   {info_count} 个")
    print(f"  {'='*60}\n")

    # 输出所有有问题的文件
    if error_files:
        # 先输出 ERROR
        print(f"\n  {'='*60}")
        print(f"  ❌ 有 ERROR 的文件（需要修复）")
        print(f"  {'='*60}")
        for fname, issues in error_files:
            error_issues = [i for i in issues if i.level == "ERROR"]
            if error_issues:
                print(f"\n  📄 {fname}")
                for issue in error_issues:
                    print(f"     ❌ {issue.message}")

        # 再输出 WARNING
        print(f"\n  {'='*60}")
        print(f"  ⚠️ 有 WARNING 的文件（建议修复）")
        print(f"  {'='*60}")
        for fname, issues in error_files:
            warning_issues = [i for i in issues if i.level == "WARNING"]
            if warning_issues:
                print(f"\n  📄 {fname}")
                for issue in warning_issues:
                    print(f"     ⚠️ {issue.message}")

        # INFO 按类别汇总
        info_categories = defaultdict(list)
        for fname, issues in error_files:
            for issue in issues:
                if issue.level == "INFO":
                    info_categories[issue.message].append(fname)

        if info_categories:
            print(f"\n  {'='*60}")
            print(f" ℹ️ INFO 类别汇总")
            print(f"  {'='*60}")
            for msg, files in info_categories.items():
                print(f"\n  {msg}")
                print(f"  影响 {len(files)} 个文件: {', '.join(files[:5])}{'...' if len(files) > 5 else ''}")

    return error_count > 0


if __name__ == "__main__":
    has_errors = main()
    sys.exit(1 if has_errors else 0)
