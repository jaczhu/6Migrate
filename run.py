#!/usr/bin/env python3
"""
6Migrate 完整调度器 - 自动执行多轮扫描
支持Windows/Linux，自动调用ZMap扫描
"""

import os
import sys
import subprocess
import argparse
import multiprocessing
import time
from pathlib import Path
from datetime import datetime

# ==================== 配置参数 ====================
TOTAL_BUDGET = 10_000_000  # 每轮1000万地址
EXPLORE_RATIOS = [1.0, 0.3, 0.2, 0.1, 0.05]  # 每轮探索比例
ZMAP_PATH = "zmap"  # 假设zmap在PATH中，否则用绝对路径
ZMAP_PORT = "443"   # 扫描端口
ZMAP_RATE = "10000" # 发送速率 10k pps

# ==================== 工具函数 ====================

def run_command(cmd, description):
    """运行命令并打印输出"""
    print(f"\n{'='*60}")
    print(f"正在执行: {description}")
    print(f"命令: {' '.join(cmd)}")
    print('='*60)
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )
    
    for line in process.stdout:
        print(line, end='')
    
    process.wait()
    return process.returncode == 0

def ensure_dir(directory):
    """确保目录存在"""
    Path(directory).mkdir(parents=True, exist_ok=True)

def scan_with_zmap(input_file, output_file, port=443, rate=10000):
    """调用ZMap进行扫描"""
    print(f"\n开始ZMap扫描: {input_file} -> {output_file}")
    
    # ZMap命令
    cmd = [
        ZMAP_PATH,
        "--target-file", input_file,
        "--output-file", output_file,
        "--port", str(port),
        "--rate", str(rate),
        "--quiet"  # 减少输出
    ]
    
    # 记录开始时间
    start_time = time.time()
    
    # 执行扫描
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # 计算耗时
    elapsed = time.time() - start_time
    
    if result.returncode == 0:
        # 统计扫描结果
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                count = sum(1 for line in f if line.strip())
            print(f"扫描完成: 发现 {count} 个存活地址, 耗时 {elapsed:.1f} 秒")
        else:
            print(f"扫描完成: 未发现存活地址, 耗时 {elapsed:.1f} 秒")
        return True
    else:
        print(f"扫描失败: {result.stderr}")
        return False

def update_active_all(active_all_file, new_active_file):
    """更新累积活跃地址文件"""
    if not os.path.exists(new_active_file):
        return 0
    
    # 读取新地址
    new_addrs = set()
    with open(new_active_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                new_addrs.add(line)
    
    if not new_addrs:
        return 0
    
    # 读取已有地址
    existing = set()
    if os.path.exists(active_all_file):
        with open(active_all_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    existing.add(line)
    
    # 合并
    all_addrs = existing | new_addrs
    added = len(all_addrs) - len(existing)
    
    # 写回
    with open(active_all_file, 'w') as f:
        f.write(f"# 累积活跃地址 (共{len(all_addrs)}个)\n")
        f.write(f"# 最后更新: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        for addr in sorted(all_addrs):
            f.write(f"{addr}\n")
    
    print(f"累积地址: {len(existing)} + {len(new_addrs)} = {len(all_addrs)} (新增 {added})")
    return added

def calculate_budgets(round_num, total_budget, ratios):
    """计算本轮探索和利用预算"""
    if round_num - 1 >= len(ratios):
        explore_ratio = ratios[-1]  # 最后一轮的比例
    else:
        explore_ratio = ratios[round_num - 1]
    
    explore_budget = int(total_budget * explore_ratio)
    exploit_budget = total_budget - explore_budget
    
    return explore_budget, exploit_budget

# ==================== 主函数 ====================

def main():
    parser = argparse.ArgumentParser(description='6Migrate 完整调度器')
    parser.add_argument('--rounds', type=int, default=3, help='扫描轮数')
    parser.add_argument('--seed-addr', default='data/seed/prefix_ip.pkl', help='种子地址文件')
    parser.add_argument('--seed-prefix', default='data/seed/prefix_seed', help='种子前缀文件')
    parser.add_argument('--noseed-prefix', default='data/noseed/prefix_noseed_noalias', help='无种子前缀文件')
    parser.add_argument('--bgp-data', default='data/bgp/rib_20260214', help='BGP数据文件')
    parser.add_argument('--output-dir', default='output', help='输出目录')
    parser.add_argument('--port', type=int, default=443, help='扫描端口')
    parser.add_argument('--rate', type=int, default=10000, help='扫描速率 (pps)')
    parser.add_argument('--budget', type=int, default=10000000, help='每轮预算')
    
    args = parser.parse_args()
    
    # 更新全局变量
    global ZMAP_PORT, ZMAP_RATE, TOTAL_BUDGET
    ZMAP_PORT = args.port
    ZMAP_RATE = args.rate
    TOTAL_BUDGET = args.budget
    
    # 创建输出目录
    base_dir = args.output_dir
    ensure_dir(base_dir)
    
    # 检查必要文件
    required_files = [
        args.seed_addr,
        args.seed_prefix,
        args.noseed_prefix,
        args.bgp_data
    ]
    
    for f in required_files:
        if not os.path.exists(f):
            print(f"错误: 文件不存在 - {f}")
            return 1
    
    # 累积活跃地址文件
    active_all_file = os.path.join(base_dir, "active_all.txt")
    
    # 检查ZMap是否可用
    try:
        subprocess.run([ZMAP_PATH, "--version"], capture_output=True)
    except FileNotFoundError:
        print(f"错误: 未找到ZMap，请确保已安装并配置PATH")
        return 1
    
    # 显示配置
    cpu_count = multiprocessing.cpu_count()
    print("="*60)
    print("6Migrate 完整调度器")
    print("="*60)
    print(f"轮数: {args.rounds}")
    print(f"每轮预算: {TOTAL_BUDGET:,} 地址")
    print(f"探索比例: {EXPLORE_RATIOS}")
    print(f"扫描端口: {ZMAP_PORT}")
    print(f"扫描速率: {ZMAP_RATE} pps")
    print(f"CPU核心: {cpu_count}")
    print("="*60)
    
    # 开始多轮扫描
    for round_num in range(1, args.rounds + 1):
        print(f"\n{'#'*60}")
        print(f"开始第 {round_num} 轮扫描")
        print(f"{'#'*60}")
        
        # 创建本轮输出目录
        round_dir = os.path.join(base_dir, f"round_{round_num}")
        ensure_dir(round_dir)
        
        # 计算本轮预算
        explore_budget, exploit_budget = calculate_budgets(
            round_num, TOTAL_BUDGET, EXPLORE_RATIOS
        )
        
        targets_list = []  # 存储所有目标文件
        
        if round_num == 1:
            # 第1轮：纯探索（模式迁移）
            patterns_dir = os.path.join(round_dir, "patterns")
            ensure_dir(patterns_dir)
            
            # 1.1 模式挖掘（从种子地址）
            if not run_command([
                sys.executable, "modules/pattern_mine.py",
                "--input", args.seed_addr,
                "--output-dir", patterns_dir,
                "--min-length", "5"
            ], "第1轮模式挖掘"):
                break
            
            # 1.2 前缀关联
            assoc_file = os.path.join(round_dir, "associations.txt")
            if not run_command([
                sys.executable, "modules/prefix_association.py",
                "--seed", args.seed_prefix,
                "--noseed", args.noseed_prefix,
                "--bgp", args.bgp_data,
                "--output", assoc_file,
                "--model", os.path.join(round_dir, "kmeans_model.pkl"),
                "--clusters", "50",
                "--topk", "15"
            ], "第1轮前缀关联"):
                break
            
            # 1.3 模式迁移（探索）
            explore_file = os.path.join(round_dir, "targets_explore.txt")
            if not run_command([
                sys.executable, "modules/pattern_migration.py",
                "--patterns-dir", patterns_dir,
                "--associations", assoc_file,
                "--output", explore_file,
                "--topk", "5"
            ], "第1轮模式迁移"):
                break
            
            targets_list.append(explore_file)
            
        else:
            # 第2+轮：探索 + 利用
            
            # 2.1 模式挖掘（利用 - 从累积地址）
            if exploit_budget > 0 and os.path.exists(active_all_file):
                exploit_file = os.path.join(round_dir, "targets_exploit.txt")
                if not run_command([
                    sys.executable, "modules/pattern_mine3.py",
                    "--addr-file", active_all_file,
                    "--prefix-file", args.noseed_prefix,
                    "--output", exploit_file,
                    "--total", str(exploit_budget),
                    "--min-length", "5",
                    "--processes", str(max(1, cpu_count - 1))
                ], f"第{round_num}轮模式挖掘"):
                    # 挖掘失败不影响继续探索
                    print("警告: 模式挖掘失败，继续探索")
                else:
                    targets_list.append(exploit_file)
            
            # 2.2 模式迁移（探索 - 复用第1轮的patterns和associations）
            if explore_budget > 0:
                # 第1轮的目录
                round1_dir = os.path.join(base_dir, "round_1")
                patterns_dir = os.path.join(round1_dir, "patterns")
                assoc_file = os.path.join(round1_dir, "associations.txt")
                
                if os.path.exists(patterns_dir) and os.path.exists(assoc_file):
                    explore_file = os.path.join(round_dir, "targets_explore.txt")
                    
                    # 修改pattern_migration.py支持指定数量
                    if not run_command([
                        sys.executable, "modules/pattern_migration.py",
                        "--patterns-dir", patterns_dir,
                        "--associations", assoc_file,
                        "--output", explore_file,
                        "--topk", "5",
                        "--budget", str(explore_budget)  # 需要修改pattern_migration.py支持
                    ], f"第{round_num}轮模式迁移"):
                        print("警告: 模式迁移失败")
                    else:
                        targets_list.append(explore_file)
                else:
                    print("警告: 第1轮数据不存在，跳过模式迁移")
        
        # 合并所有目标文件
        if not targets_list:
            print("错误: 没有生成任何目标地址")
            break
        
        targets_file = os.path.join(round_dir, "targets_all.txt")
        
        # 合并文件
        with open(targets_file, 'w') as out_f:
            out_f.write(f"# 第{round_num}轮目标地址\n")
            out_f.write(f"# 生成时间: {datetime.now()}\n")
            out_f.write(f"# 探索预算: {explore_budget}, 利用预算: {exploit_budget}\n\n")
            
            total_targets = 0
            for tf in targets_list:
                if os.path.exists(tf):
                    with open(tf, 'r') as in_f:
                        for line in in_f:
                            if line.strip() and not line.startswith('#'):
                                out_f.write(line)
                                total_targets += 1
        
        print(f"\n第{round_num}轮共生成了 {total_targets} 个目标地址")
        
        # 扫描
        active_file = os.path.join(round_dir, "active.txt")
        print(f"\n开始扫描第{round_num}轮目标地址...")
        
        scan_success = scan_with_zmap(
            targets_file, 
            active_file,
            port=ZMAP_PORT,
            rate=ZMAP_RATE
        )
        
        if not scan_success:
            print("扫描失败，是否继续？(y/n)")
            if input().lower() != 'y':
                break
        
        # 统计本轮结果
        if os.path.exists(active_file):
            with open(active_file, 'r') as f:
                active_count = sum(1 for line in f if line.strip())
            print(f"第{round_num}轮发现存活地址: {active_count} 个")
            
            # 更新累积文件
            update_active_all(active_all_file, active_file)
        else:
            print(f"第{round_num}轮未发现存活地址")
        
        # 可选：如果连续两轮没有新地址，提前结束
        if round_num > 1 and active_count == 0:
            print("连续一轮未发现新地址，是否提前结束？(y/n)")
            if input().lower() == 'y':
                break
    
    # 生成最终报告
    report_file = os.path.join(base_dir, "final_report.txt")
    with open(report_file, 'w') as f:
        f.write("="*60 + "\n")
        f.write("6Migrate 扫描报告\n")
        f.write("="*60 + "\n\n")
        
        if os.path.exists(active_all_file):
            with open(active_all_file, 'r') as af:
                total_active = sum(1 for line in af if line.strip() and not line.startswith('#'))
            f.write(f"总发现活跃地址: {total_active}\n\n")
        
        f.write("各轮统计:\n")
        for round_num in range(1, args.rounds + 1):
            round_dir = os.path.join(base_dir, f"round_{round_num}")
            active_file = os.path.join(round_dir, "active.txt")
            if os.path.exists(active_file):
                with open(active_file, 'r') as af:
                    count = sum(1 for line in af if line.strip())
                f.write(f"  第{round_num}轮: {count} 个\n")
    
    print("\n" + "="*60)
    print("所有扫描轮次完成")
    print(f"报告已保存: {report_file}")
    print("="*60)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(130)
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)