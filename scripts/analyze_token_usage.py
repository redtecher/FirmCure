#!/usr/bin/env python3
"""
Token 使用量分析脚本

分析 FirmCure 三阶段的 token 消耗情况
"""

import json
from pathlib import Path
from typing import Dict, List, Optional


def load_phase_result(phase_dir: Path, result_file: str) -> Optional[Dict]:
    """加载阶段结果文件"""
    result_path = phase_dir / result_file
    if not result_path.exists():
        return None

    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {result_path}: {e}")
        return None


def analyze_case(case_dir: Path) -> Dict:
    """分析单个案例的 token 使用情况"""
    result = {
        'case_id': case_dir.name,
        'phase1': None,
        'phase2': None,
        'phase3': None,
        'total': None
    }

    # Phase1
    phase1_dir = case_dir / "phase1"
    if phase1_dir.exists():
        phase1_data = load_phase_result(phase1_dir, "phase1_analysis.json")
        if phase1_data and 'token_usage' in phase1_data:
            result['phase1'] = phase1_data['token_usage']

    # Phase2 (通常没有 LLM 调用，除非有特殊情况)
    phase2_dir = case_dir / "phase2"
    if phase2_dir.exists():
        phase2_data = load_phase_result(phase2_dir, "phase2_result.json")
        if phase2_data and 'token_usage' in phase2_data:
            result['phase2'] = phase2_data['token_usage']

    # Phase3
    phase3_dir = case_dir / "phase3"
    if phase3_dir.exists():
        phase3_data = load_phase_result(phase3_dir, "phase3_result.json")
        if phase3_data and 'token_usage' in phase3_data:
            result['phase3'] = phase3_data['token_usage']

            # 提取每次迭代的 token 使用
            if 'repair_history' in phase3_data:
                result['phase3_iterations'] = []
                for repair in phase3_data['repair_history']:
                    if 'token_usage' in repair and repair['token_usage']:
                        result['phase3_iterations'].append({
                            'iteration': repair.get('iteration', 0),
                            'expert': repair.get('expert_name', 'unknown'),
                            'tokens': repair['token_usage']
                        })

    # 计算总计
    total_tokens = 0
    total_prompt = 0
    total_completion = 0

    for phase in ['phase1', 'phase3']:
        if result[phase]:
            total_tokens += result[phase].get('total_tokens', 0)
            total_prompt += result[phase].get('prompt_tokens', 0)
            total_completion += result[phase].get('completion_tokens', 0)

    if total_tokens > 0:
        result['total'] = {
            'total_tokens': total_tokens,
            'prompt_tokens': total_prompt,
            'completion_tokens': total_completion
        }

    return result


def main():
    scratch_dir = Path("/home/iot/Desktop/FirmCure/scratch")

    if not scratch_dir.exists():
        print(f"Scratch directory not found: {scratch_dir}")
        return

    cases = []

    # 分析所有三阶段完整的案例
    for case_dir in sorted(scratch_dir.iterdir()):
        if not case_dir.is_dir():
            continue

        # 只分析三阶段完整的案例
        if not (case_dir / "phase1").exists() or \
           not (case_dir / "phase2").exists() or \
           not (case_dir / "phase3").exists():
            continue

        result = analyze_case(case_dir)
        cases.append(result)

    # 输出结果
    print("=" * 100)
    print("FirmCure Token 使用量分析")
    print("=" * 100)
    print()
    print(f"{'案例':<8} {'Phase1':<20} {'Phase3':<20} {'总计':<20}")
    print("-" * 100)

    for case in cases:
        case_id = case['case_id']

        # Phase1
        if case['phase1']:
            p1_str = f"{case['phase1']['total_tokens']:,} tokens"
        else:
            p1_str = "N/A"

        # Phase3
        if case['phase3']:
            p3_str = f"{case['phase3']['total_tokens']:,} tokens"
            if case.get('phase3_iterations'):
                p3_str += f" ({len(case['phase3_iterations'])} iter)"
        else:
            p3_str = "N/A"

        # 总计
        if case['total']:
            total_str = f"{case['total']['total_tokens']:,} tokens"
        else:
            total_str = "N/A"

        print(f"{case_id:<8} {p1_str:<20} {p3_str:<20} {total_str:<20}")

    print()
    print("=" * 100)
    print("统计摘要")
    print("=" * 100)

    # 统计
    phase1_tokens = [c['phase1']['total_tokens'] for c in cases if c['phase1']]
    phase3_tokens = [c['phase3']['total_tokens'] for c in cases if c['phase3']]
    total_tokens = [c['total']['total_tokens'] for c in cases if c['total']]

    print(f"分析案例数: {len(cases)}")
    print()

    if phase1_tokens:
        print(f"Phase1 (静态分析) Token 使用:")
        print(f"  有数据案例: {len(phase1_tokens)} / {len(cases)}")
        print(f"  平均: {sum(phase1_tokens) / len(phase1_tokens):,.0f} tokens")
        print(f"  最少: {min(phase1_tokens):,} tokens")
        print(f"  最多: {max(phase1_tokens):,} tokens")
        print()

    if phase3_tokens:
        print(f"Phase3 (运行时干预) Token 使用:")
        print(f"  有数据案例: {len(phase3_tokens)} / {len(cases)}")
        print(f"  平均: {sum(phase3_tokens) / len(phase3_tokens):,.0f} tokens")
        print(f"  最少: {min(phase3_tokens):,} tokens")
        print(f"  最多: {max(phase3_tokens):,} tokens")
        print()

    if total_tokens:
        print(f"总体 Token 使用:")
        print(f"  平均: {sum(total_tokens) / len(total_tokens):,.0f} tokens")
        print(f"  最少: {min(total_tokens):,} tokens")
        print(f"  最多: {max(total_tokens):,} tokens")
        print()

    # Phase3 迭代详情
    print("=" * 100)
    print("Phase3 迭代详情 (有数据的案例)")
    print("=" * 100)

    for case in cases:
        if case.get('phase3_iterations'):
            print(f"\n案例 {case['case_id']}:")
            for iter_data in case['phase3_iterations']:
                tokens = iter_data['tokens']
                print(f"  Iteration {iter_data['iteration']}: "
                      f"{iter_data['expert']:<15} - "
                      f"{tokens['total_tokens']:,} tokens "
                      f"(prompt: {tokens['prompt_tokens']:,}, "
                      f"completion: {tokens['completion_tokens']:,})")


if __name__ == "__main__":
    main()
