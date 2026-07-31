#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
脚本名称: analyze_results.py
功能描述: 解析 garak 生成的 .report.jsonl 文件，提取攻击成功率（ASR）
输入参数: 一个或多个 .report.jsonl 文件路径
输出文件: summary.json（ASR汇总表）+ case_studies.json（典型案例）
用法示例: python analyze_results.py garak.xxxx.report.jsonl
================================================================================
"""

import json
import sys
from collections import defaultdict


def print_header(text, char="=", width=70):
    """打印带分隔线的标题"""
    print("\n" + char * width)
    print(f"  {text}")
    print(char * width)


def load_reports(file_paths):
    """读取并解析 JSONL 报告文件"""
    attempts_by_uuid = defaultdict(list)
    eval_records = []

    for path in file_paths:
        print(f"[读取] {path}")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if record.get("entry_type") == "attempt":
                    attempts_by_uuid[record["uuid"]].append(record)
                elif record.get("entry_type") == "eval":
                    eval_records.append(record)

    return attempts_by_uuid, eval_records


def extract_final_attempts(attempts_by_uuid):
    """提取每个 UUID 的最终 attempt 记录"""
    result = []
    for uuid, records in attempts_by_uuid.items():
        # 优先取包含 detector_results 的记录
        with_detector = [r for r in records if r.get("detector_results")]
        result.append(with_detector[-1] if with_detector else records[-1])
    return result


def compute_asr(eval_records):
    """计算攻击成功率"""
    rows = []
    total_hits = 0
    total_tests = 0

    for rec in eval_records:
        probe = rec.get("probe", "未知探针")
        detector = rec.get("detector", "未知检测器")
        tested = rec.get("total_evaluated", 0)
        hits = rec.get("fails", 0)
        asr = (hits / tested * 100) if tested > 0 else 0.0

        total_hits += hits
        total_tests += tested
        rows.append({
            "probe": probe,
            "detector": detector,
            "asr": asr,
            "total": tested,
            "hits": hits
        })

    overall_asr = (total_hits / total_tests * 100) if total_tests > 0 else 0.0
    return rows, total_hits, total_tests, overall_asr


def extract_case_studies(attempts):
    """提取典型案例（每个探针取一个命中样本）"""
    seen = set()
    cases = []

    for rec in attempts:
        probe = rec.get("probe_classname", "未知探针")
        if probe in seen:
            continue

        # 查找命中的检测器
        det_results = rec.get("detector_results", {})
        hit_idx = None
        hit_detector = None

        for det_name, scores in det_results.items():
            for i, score in enumerate(scores):
                if score and score > 0:
                    hit_idx = i
                    hit_detector = det_name
                    break
            if hit_idx is not None:
                break

        if hit_idx is None:
            continue

        prompt = rec["prompt"]["turns"][0]["content"]["text"]
        output = rec["outputs"][hit_idx]["text"]

        cases.append({
            "probe": probe,
            "detector": hit_detector,
            "prompt": prompt[:400] + "..." if len(prompt) > 400 else prompt,
            "output": output[:400] + "..." if len(output) > 400 else output,
        })
        seen.add(probe)

    return cases


def main():
    # ---------- 命令行参数检查 ----------
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n错误：请至少指定一个 .report.jsonl 文件路径")
        sys.exit(1)

    # ---------- 加载数据 ----------
    attempts_by_uuid, eval_records = load_reports(sys.argv[1:])

    if not attempts_by_uuid:
        print("[错误] 未找到任何 attempt 记录")
        sys.exit(1)
    if not eval_records:
        print("[错误] 未找到任何 eval 记录")
        sys.exit(1)

    final_attempts = extract_final_attempts(attempts_by_uuid)
    print(f"[信息] 有效测试数: {len(final_attempts)} 条")
    print(f"[信息] 汇总记录数: {len(eval_records)} 条")

    # ---------- 计算 ASR ----------
    rows, total_hits, total_tests, overall_asr = compute_asr(eval_records)

    # ---------- 打印结果 ----------
    print_header("测评结果汇总")
    print(f"{'探针名称':<45} {'检测器':<28} {'ASR':>8} {'命中/总数':>12}")
    print("-" * 95)

    for r in rows:
        print(f"{r['probe']:<45} {r['detector']:<28} {r['asr']:>7.1f}% {r['hits']:>4d}/{r['total']:<5d}")

    print("-" * 95)
    print(f"{'总体':<45} {'':<28} {overall_asr:>7.1f}% {total_hits:>4d}/{total_tests:<5d}")
    print("=" * 95)

    # ---------- 保存 summary.json ----------
    with open("summary.json", "w", encoding="utf-8") as f:
        json.dump({
            "rows": rows,
            "total_hits": total_hits,
            "total_tests": total_tests,
            "overall_asr": overall_asr
        }, f, ensure_ascii=False, indent=2)
    print("\n[已保存] summary.json")

    # ---------- 提取并保存典型案例 ----------
    cases = extract_case_studies(final_attempts)
    with open("case_studies.json", "w", encoding="utf-8") as f:
        json.dump(cases, f, ensure_ascii=False, indent=2)
    print(f"[已保存] case_studies.json（共 {len(cases)} 个案例）")

    print("\n[完成]")


if __name__ == "__main__":
    main()