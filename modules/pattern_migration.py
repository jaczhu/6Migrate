#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import pickle
import gzip
import ipaddress
from collections import defaultdict
import argparse  # 新增
import sys

# ==================== 移除硬编码全局变量 ====================
# patterns_dir = "output/patterns_pkl"
# associations_file = "output/prefix_associations.txt"
# output_dir = "output/migrated_addresses"
# index_file = os.path.join(patterns_dir, "index.pkl")

# ==================== 新增：参数解析函数 ====================
def parse_arguments():
    """解析命令行参数（极简版）"""
    parser = argparse.ArgumentParser(
        description='IPv6地址模式迁移工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --patterns-dir output/round_1/patterns --associations output/round_1/associations.txt --output output/round_1/targets.txt
  %(prog)s -p output/patterns -a associations.txt -o targets.txt --topk 10
        """
    )
    
    parser.add_argument('--patterns-dir', '-p', required=True,
                        help='模式文件目录 (包含各前缀的.pkl文件)')
    
    parser.add_argument('--associations', '-a', required=True,
                        help='前缀关联文件 (由prefix_association.py生成)')
    
    parser.add_argument('--output', '-o', required=True,
                        help='输出文件路径 (生成的地址列表)')
    
    parser.add_argument('--topk', '-k',
                        type=int, default=5,
                        help='每个无种子前缀选择的最多模式数 (默认: 5)')
    
    parser.add_argument('--no-index',
                        action='store_true',
                        help='不使用索引文件 (直接搜索文件)')
    
    parser.add_argument('--budget', '-b', type=int, default=0, 
                    help='生成地址数量上限 (0表示无限制)')
    
    return parser.parse_args()

# ==================== 工具函数（完全不变） ====================

def load_patterns_from_pkl(filepath):
    """
    从pkl文件加载模式数据
    返回: [(pattern_str, count, ratio, addresses), ...]
    addresses是列表，包含该模式下的所有地址
    """
    patterns = []
    
    try:
        if filepath.endswith('.gz'):
            with gzip.open(filepath, 'rb') as f:
                data = pickle.load(f)
        else:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
        
        prefix = data.get('prefix', '')
        metadata = data.get('metadata', {})
        total_addresses = metadata.get('total_addresses', 0)
        
        for p in data.get('patterns', []):
            pattern_str = p['pattern_with_fixed']
            addresses = p['addresses']
            count = len(addresses)
            ratio = (count / total_addresses * 100) if total_addresses > 0 else 0
            
            patterns.append((pattern_str, count, ratio, addresses))
            
    except Exception as e:
        print(f"Error loading pkl file {filepath}: {e}")
        
    return patterns

def prefix_to_pkl_filename(prefix):
    """将IPv6前缀转换为pkl文件名格式"""
    filename1 = prefix.replace('/', '_')
    filename2 = filename1.replace(':', '_')
    filename2 = re.sub(r'_+', '_', filename2)
    filename = filename2 + "_patterns.pkl"
    return filename

def prefix_to_pkl_gz_filename(prefix):
    """将IPv6前缀转换为压缩的pkl文件名格式"""
    return prefix_to_pkl_filename(prefix).replace('.pkl', '.pkl.gz')

def replace_prefix_in_address(addr, old_prefix, new_prefix):
    """将地址中的旧前缀替换为新前缀"""
    try:
        ip = ipaddress.IPv6Address(addr)
        new_network = ipaddress.IPv6Network(new_prefix, strict=False)
        
        prefix_len = new_network.prefixlen
        
        ip_bits = format(int(ip), '0128b')
        new_prefix_bits = format(int(new_network.network_address), '0128b')
        
        new_ip_bits = new_prefix_bits[:prefix_len] + ip_bits[prefix_len:]
        
        new_ip_int = int(new_ip_bits, 2)
        new_ip = ipaddress.IPv6Address(new_ip_int)
        
        return str(new_ip)
        
    except Exception as e:
        print(f"Error replacing prefix in address '{addr}': {e}")
        return addr

def load_index_file(index_file):
    """加载索引文件，获取前缀到文件的映射"""
    if os.path.exists(index_file):
        try:
            with open(index_file, 'rb') as f:
                return pickle.load(f)
        except:
            return None
    return None

def find_pattern_file(prefix, patterns_dir, use_compression=False):
    """查找前缀对应的模式文件（支持普通pkl和压缩pkl）"""
    pkl_file = os.path.join(patterns_dir, prefix_to_pkl_filename(prefix))
    if os.path.exists(pkl_file):
        return pkl_file
    
    gz_file = os.path.join(patterns_dir, prefix_to_pkl_gz_filename(prefix))
    if os.path.exists(gz_file):
        return gz_file
    
    return None

# ==================== 新增：加载关联文件函数 ====================
def load_associations(filename):
    """加载关联文件，返回 {noseed_prefix: [(seed_prefix, similarity, method), ...]}"""
    associations = {}
    
    print(f"读取关联文件: {filename}")
    
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split('\t')
            if len(parts) >= 2:
                noseed_prefix = parts[0]
                seed_prefix = parts[1]
                similarity = float(parts[2]) if len(parts) > 2 else 1.0
                method = parts[3] if len(parts) > 3 else 'unknown'
                
                if noseed_prefix not in associations:
                    associations[noseed_prefix] = []
                associations[noseed_prefix].append((seed_prefix, similarity, method))
    
    print(f"加载了 {len(associations)} 个无种子前缀的关联关系")
    return associations

# ==================== 主函数（重构） ====================
def main():
    """主函数"""
    # 1. 解析参数
    args = parse_arguments()
    
    # 2. 显示配置
    print("="*60)
    print("6Migrate: IPv6地址模式迁移")
    print("="*60)
    print(f"模式文件目录: {args.patterns_dir}")
    print(f"关联文件: {args.associations}")
    print(f"输出文件: {args.output}")
    print(f"每个前缀选择模式数: {args.topk}")
    print("="*60)
    
    # 3. 检查目录和文件
    if not os.path.isdir(args.patterns_dir):
        print(f"错误: 模式目录不存在 - {args.patterns_dir}")
        return 1
    
    if not os.path.isfile(args.associations):
        print(f"错误: 关联文件不存在 - {args.associations}")
        return 1
    
    # 4. 创建输出目录
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # 5. 尝试加载索引文件
    index = None
    if not args.no_index:
        index_file = os.path.join(args.patterns_dir, "index.pkl")
        index = load_index_file(index_file)
        if index:
            print(f"加载索引文件成功，包含 {index['metadata']['total_prefixes']} 个前缀")
        else:
            print("未找到索引文件，将直接搜索文件")
    
    # 6. 读取关联关系
    associations = load_associations(args.associations)
    
    # 7. 按无种子前缀分组（已经是分组好的，不需要再处理）
    noseed_to_seeds = associations
    
    # 8. 开始处理
    total_prefixes = len(noseed_to_seeds)
    processed = 0
    total_addresses = 0
    missing_files = 0
    
    print(f"\n开始迁移，共 {total_prefixes} 个无种子前缀")
    
    with open(args.output, 'w', encoding='utf-8') as f:
        # 添加文件头
        f.write(f"# 6Migrate 生成的IPv6地址\n")
        f.write(f"# 模式目录: {args.patterns_dir}\n")
        f.write(f"# 关联文件: {args.associations}\n")
        f.write(f"# 每个前缀模式数: {args.topk}\n\n")
        
        # 处理每个无种子前缀
        for noseed_prefix, seed_list in noseed_to_seeds.items():
            processed += 1
            
            # 每100个前缀打印一次进度
            if processed % 100 == 0:
                print(f"\r进度: {processed}/{total_prefixes} ({processed/total_prefixes*100:.1f}%) | "
                      f"地址数: {total_addresses} | 缺失: {missing_files}", end="", flush=True)
            
            # 收集所有种子前缀的模式
            all_patterns = []  # (pattern_str, count, ratio, addresses, seed_prefix)
            
            for seed_prefix, similarity, method in seed_list:
                # 查找种子前缀的模式文件
                if index and seed_prefix in index['file_mapping']:
                    # 使用索引快速定位
                    pattern_file = os.path.join(args.patterns_dir, index['file_mapping'][seed_prefix])
                    if not os.path.exists(pattern_file):
                        # 如果文件不存在，回退到搜索
                        pattern_file = find_pattern_file(seed_prefix, args.patterns_dir)
                else:
                    pattern_file = find_pattern_file(seed_prefix, args.patterns_dir)
                
                if not pattern_file:
                    print(f"\n  警告: 未找到 {seed_prefix} 的模式文件")
                    missing_files += 1
                    continue
                
                # 加载模式
                patterns = load_patterns_from_pkl(pattern_file)
                
                # 添加到总列表（可以乘以相似度作为权重，但先保持简单）
                for pattern_str, count, ratio, addresses in patterns:
                    all_patterns.append((pattern_str, count, ratio, addresses, seed_prefix, similarity))
            
            # 按count排序，选择前topk个
            if all_patterns:
                # 可以按 count * similarity 排序，但为简单先按count
                all_patterns.sort(key=lambda x: x[1], reverse=True)
                selected_patterns = all_patterns[:args.topk]
                
                # 迁移地址
                for pattern, count, ratio, addresses, source_seed, sim in selected_patterns:
                    for addr in addresses:
                        if args.budget > 0 and total_addresses >= args.budget:
                            break
                        migrated_addr = replace_prefix_in_address(addr, source_seed, noseed_prefix)
                        f.write(f"{migrated_addr}\n")
                        total_addresses += 1
                    if args.budget > 0 and total_addresses >= args.budget:
                        break
    
    print(f"\n\n迁移完成!")
    print(f"处理无种子前缀数: {processed}")
    print(f"生成地址总数: {total_addresses}")
    print(f"缺失模式文件数: {missing_files}")
    print(f"输出文件: {args.output}")
    
    return 0

# ==================== 程序入口 ====================
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