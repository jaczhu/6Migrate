#!/usr/bin/env python3
"""
6Migrate: IPv6地址模式挖掘
输入: 种子地址文件 (pkl格式)
输出: 每个种子前缀的模式文件
"""

import pickle
import numpy as np
from collections import defaultdict, Counter
from ipaddress import IPv6Address
import os
import math
from tqdm import tqdm
import gzip
import re
import argparse
import sys
import datetime

# ==================== 移除全局硬编码变量 ====================
# 原来的这行要删除:
# INPUT_FILE = "../../hitlist/prefix_ip.pkl"
# OUTPUT_DIR = "output/patterns_pkl"
# MIN_PATTERN_LENGTH = 5
# COMPRESS_PKL = False
# SAVE_INDEX = True

# ==================== 工具函数 ====================

def ipv6_to_hex_array(addr):
    """将IPv6地址转换为32个字符的数组"""
    try:
        ip_int = int(IPv6Address(addr))
        hex_str = f"{ip_int:032x}"
        return list(hex_str)
    except:
        return None

def entropy(counts, total):
    """计算熵值"""
    e = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            e -= p * math.log2(p)
    return e

def prefix_to_filename(prefix):
    """将前缀转换为安全的文件名"""
    safe_name = prefix.replace('/', '_').replace(':', '_')
    safe_name = re.sub(r'_+', '_', safe_name)
    return f"{safe_name}_patterns.pkl"

def prefix_to_filename_gz(prefix):
    """将前缀转换为压缩文件的文件名"""
    return prefix_to_filename(prefix).replace('.pkl', '.pkl.gz')

# ==================== 节点类（保持不变） ====================

class PatternNode:
    __slots__ = ('addresses', '_hex_arrays', 'pattern', 'children', 'is_leaf', 'final_pattern', 'final_pattern_fixed')
    
    def __init__(self, addresses, pattern=None):
        self.addresses = addresses
        self._hex_arrays = None
        self.pattern = pattern if pattern else ['*'] * 32
        self.children = []
        self.is_leaf = False
        self.final_pattern = None
        self.final_pattern_fixed = None
    
    def _get_hex_arrays(self):
        """延迟加载hex_arrays"""
        if self._hex_arrays is None:
            self._hex_arrays = []
            for addr in self.addresses:
                ha = ipv6_to_hex_array(addr)
                if ha:
                    self._hex_arrays.append(ha)
        return self._hex_arrays
    
    def calculate_wildcard_entropy(self):
        """计算熵值"""
        hex_arrays = self._get_hex_arrays()
        wildcard_positions = [i for i, ch in enumerate(self.pattern) if ch == '*']
        if not wildcard_positions:
            return {}
        
        position_values = defaultdict(list)
        for ha in hex_arrays:
            for pos in wildcard_positions:
                position_values[pos].append(ha[pos])
        
        entropies = {}
        for pos, values in position_values.items():
            counter = Counter(values)
            entropies[pos] = entropy(counter, len(values))
        
        return entropies
    
    def split(self, split_pos):
        """分裂节点"""
        hex_arrays = self._get_hex_arrays()
        groups = defaultdict(list)
        
        for idx, ha in enumerate(hex_arrays):
            groups[ha[split_pos]].append(idx)
        
        children = []
        for value, indices in groups.items():
            child_addrs = [self.addresses[i] for i in indices]
            new_pattern = self.pattern.copy()
            new_pattern[split_pos] = value
            children.append(PatternNode(child_addrs, new_pattern))
        
        return children
    
    def to_pattern_string(self):
        """将模式数组转换为字符串"""
        groups = []
        for i in range(0, 32, 4):
            group = ''.join(self.pattern[i:i+4])
            groups.append(group)
        return ':'.join(groups)
    
    def to_pattern_string_with_fixed_bits(self):
        """将固定不变的字符位从通配符转换为实际字符"""
        if not self.addresses:
            return self.to_pattern_string()
        
        hex_arrays = self._get_hex_arrays()
        if not hex_arrays:
            return self.to_pattern_string()
        
        new_pattern = self.pattern.copy()
        
        for i, ch in enumerate(self.pattern):
            if ch == '*':
                values_at_pos = [ha[i] for ha in hex_arrays]
                if len(set(values_at_pos)) == 1:
                    new_pattern[i] = values_at_pos[0]
        
        groups = []
        for i in range(0, 32, 4):
            group = ''.join(new_pattern[i:i+4])
            groups.append(group)
        return ':'.join(groups)
    
    def mark_leaf(self):
        """标记为叶子节点并清理中间数据"""
        self.is_leaf = True
        self.final_pattern = self.to_pattern_string()
        self.final_pattern_fixed = self.to_pattern_string_with_fixed_bits()
        self._hex_arrays = None
    
    def cleanup(self):
        """清理中间节点的临时数据"""
        self._hex_arrays = None

# ==================== 挖掘器类（保持不变） ====================

class PatternMiner:
    def __init__(self, min_wildcards=5):
        self.min_wildcards = min_wildcards
    
    def _should_stop_splitting(self, node):
        wildcard_count = node.pattern.count('*')
        if wildcard_count < self.min_wildcards:
            return True
        return False
    
    def _build_tree(self, node):
        if self._should_stop_splitting(node):
            node.mark_leaf()
            return
        
        entropies = node.calculate_wildcard_entropy()
        if not entropies:
            node.mark_leaf()
            return
        
        split_pos = min(entropies, key=entropies.get)
        children = node.split(split_pos)
        
        node.cleanup()
        
        for child in children:
            self._build_tree(child)
            node.children.append(child)
    
    def _collect_patterns(self, node, patterns):
        if node.is_leaf or not node.children:
            patterns.append({
                'pattern_with_fixed': node.final_pattern_fixed,
                'addresses': node.addresses,
                'count': len(node.addresses)
            })
        else:
            for child in node.children:
                self._collect_patterns(child, patterns)
    
    def mine(self, addresses):
        if len(addresses) < 2:
            return [{
                'pattern_with_fixed': list(addresses)[0] if addresses else "",
                'addresses': list(addresses),
                'count': len(addresses)
            } for addr in addresses]
        
        root = PatternNode(addresses)
        self._build_tree(root)
        
        patterns = []
        self._collect_patterns(root, patterns)
        
        return patterns

# ==================== 新增：参数解析函数 ====================

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='IPv6地址模式挖掘工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --input data/seed/prefix_ip.pkl --output-dir output/round_1/patterns
  %(prog)s --input data/seed/prefix_ip.pkl --output-dir output/patterns --min-length 8 --compress
        """
    )
    
    parser.add_argument('--input', '-i',
                        required=True,
                        help='输入文件路径 (pkl格式，包含前缀到地址的映射)')
    
    parser.add_argument('--output-dir', '-o',
                        required=True,
                        help='输出目录，模式文件将保存在这里')
    
    parser.add_argument('--min-length', '-m',
                        type=int,
                        default=5,
                        help='停止划分的最小通配符数量 (默认: 5)')
    
    parser.add_argument('--compress', '-c',
                        action='store_true',
                        help='是否压缩输出文件 (使用gzip)')
    
    parser.add_argument('--no-index',
                        action='store_true',
                        help='不保存索引文件 (默认保存)')
    
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='显示详细输出')
    
    return parser.parse_args()

# ==================== 修改后的数据加载函数 ====================

def load_address_data(filename):
    """加载地址数据，带错误处理"""
    print(f"加载地址数据: {filename}")
    try:
        with open(filename, 'rb') as f:
            data = pickle.load(f)
        print(f"加载了 {len(data)} 个前缀")
        return data
    except FileNotFoundError:
        print(f"错误: 文件不存在 - {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 无法加载文件 - {e}")
        sys.exit(1)

# ==================== 修改后的保存函数 ====================

def save_prefix_patterns_pkl(prefix, patterns, output_dir, compress=False):
    """
    将前缀的模式保存为pkl文件
    返回保存的文件路径
    """
    data = {
        "prefix": prefix,
        "patterns": [
            {
                "pattern_with_fixed": p['pattern_with_fixed'],
                "addresses": p['addresses']
            }
            for p in patterns
        ],
        "metadata": {
            "total_addresses": sum(p['count'] for p in patterns),
            "total_patterns": len(patterns),
            "created": datetime.datetime.now().isoformat()
        }
    }
    
    if compress:
        filename = prefix_to_filename_gz(prefix)
        filepath = os.path.join(output_dir, filename)
        with gzip.open(filepath, 'wb') as f:
            pickle.dump(data, f)
    else:
        filename = prefix_to_filename(prefix)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
    
    return filepath

# ==================== 新增：更新索引函数 ====================

def update_index(index_file, prefix_data):
    """更新全局索引文件"""
    index = {
        "prefixes": [],
        "file_mapping": {},
        "pattern_counts": {},
        "total_addresses": {},
        "metadata": {
            "created": datetime.datetime.now().isoformat(),
            "total_prefixes": 0,
            "total_patterns": 0,
            "total_addresses": 0
        }
    }
    
    # 如果索引文件已存在，加载它
    if os.path.exists(index_file):
        try:
            with open(index_file, 'rb') as f:
                index = pickle.load(f)
        except:
            pass
    
    # 更新索引
    for prefix, (patterns, filepath) in prefix_data.items():
        if prefix not in index["prefixes"]:
            index["prefixes"].append(prefix)
        index["file_mapping"][prefix] = os.path.basename(filepath)
        index["pattern_counts"][prefix] = len(patterns)
        total_addrs = sum(p['count'] for p in patterns)
        index["total_addresses"][prefix] = total_addrs
    
    # 更新元数据
    index["metadata"] = {
        "created": datetime.datetime.now().isoformat(),
        "total_prefixes": len(index["prefixes"]),
        "total_patterns": sum(index["pattern_counts"].values()),
        "total_addresses": sum(index["total_addresses"].values())
    }
    
    # 保存索引
    with open(index_file, 'wb') as f:
        pickle.dump(index, f)
    
    return index

# ==================== 修改后的主函数 ====================

def main():
    """主函数"""
    # 1. 解析命令行参数
    args = parse_arguments()
    
    # 2. 显示配置信息
    print("="*60)
    print("6Migrate: IPv6地址模式挖掘")
    print("="*60)
    print(f"输入文件: {args.input}")
    print(f"输出目录: {args.output_dir}")
    print(f"最小通配符数: {args.min_length}")
    print(f"压缩文件: {'是' if args.compress else '否'}")
    print(f"保存索引: {'否' if args.no_index else '是'}")
    print("="*60)
    
    # 3. 创建输出目录
    os.makedirs(args.output_dir, exist_ok=True)
    
    # 4. 加载地址数据
    prefix_data = load_address_data(args.input)
    
    # 5. 统计信息
    total_prefixes = len(prefix_data)
    processed = 0
    total_patterns = 0
    total_addresses_processed = 0
    skipped_prefixes = 0
    
    # 记录每个前缀的保存信息
    saved_prefix_info = {}
    
    # 6. 创建挖掘器
    miner = PatternMiner(min_wildcards=args.min_length)
    
    print(f"\n开始挖掘模式...")
    
    # 7. 为每个前缀进行模式挖掘
    for prefix, addresses in tqdm(prefix_data.items(), desc="挖掘模式"):
        try:
            if len(addresses) < 2:
                patterns = [{
                    'pattern_with_fixed': list(addresses)[0] if addresses else "",
                    'addresses': list(addresses),
                    'count': len(addresses)
                }]
            else:
                patterns = miner.mine(list(addresses))
            
            # 保存为pkl文件
            filepath = save_prefix_patterns_pkl(
                prefix, 
                patterns, 
                args.output_dir, 
                compress=args.compress
            )
            
            # 记录保存信息
            saved_prefix_info[prefix] = (patterns, filepath)
            
            processed += 1
            total_patterns += len(patterns)
            total_addresses_processed += len(addresses)
            
            if args.verbose and processed % 100 == 0:
                print(f"\n  已处理 {processed} 个前缀，发现 {total_patterns} 个模式")
                
        except Exception as e:
            print(f"\n  处理前缀 {prefix} 时出错: {e}")
            skipped_prefixes += 1
            continue
    
    # 8. 保存全局索引（除非指定 --no-index）
    if not args.no_index and saved_prefix_info:
        index_file = os.path.join(args.output_dir, "index.pkl")
        index = update_index(index_file, saved_prefix_info)
        
        # 同时保存文本格式的索引
        txt_index_file = os.path.join(args.output_dir, "index.txt")
        with open(txt_index_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("6Migrate 地址模式挖掘索引\n")
            f.write("="*60 + "\n\n")
            f.write(f"创建时间: {index['metadata']['created']}\n")
            f.write(f"总前缀数: {index['metadata']['total_prefixes']}\n")
            f.write(f"总模式数: {index['metadata']['total_patterns']}\n")
            f.write(f"总地址数: {index['metadata']['total_addresses']}\n\n")
    
    # 9. 保存汇总信息
    summary_file = os.path.join(args.output_dir, "summary.txt")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("6Migrate 地址模式挖掘汇总\n")
        f.write("="*60 + "\n\n")
        f.write(f"处理时间: {datetime.datetime.now().isoformat()}\n\n")
        f.write(f"总前缀数: {total_prefixes}\n")
        f.write(f"成功处理: {processed}\n")
        f.write(f"跳过前缀: {skipped_prefixes}\n")
        f.write(f"总地址数: {total_addresses_processed}\n")
        f.write(f"总模式数: {total_patterns}\n")
        if processed > 0:
            f.write(f"平均每前缀模式数: {total_patterns/processed:.2f}\n")
            f.write(f"平均每模式地址数: {total_addresses_processed/total_patterns:.2f}\n\n")
        f.write(f"参数设置:\n")
        f.write(f"  输入文件: {args.input}\n")
        f.write(f"  输出目录: {args.output_dir}\n")
        f.write(f"  最小通配符数: {args.min_length}\n")
        f.write(f"  压缩文件: {args.compress}\n")
    
    # 10. 输出最终统计
    print("\n" + "="*60)
    print(f"挖掘完成！")
    print(f"处理前缀数: {processed}")
    print(f"总地址数: {total_addresses_processed}")
    print(f"发现模式数: {total_patterns}")
    if processed > 0:
        print(f"平均每前缀模式数: {total_patterns/processed:.2f}")
    print(f"结果保存在: {args.output_dir}")
    print("="*60)
    
    # 11. 返回状态码（0表示成功，1表示有错误）
    return 0 if skipped_prefixes < total_prefixes else 1

# ==================== 辅助函数（保持不变） ====================

def load_prefix_patterns(prefix, patterns_dir, compressed=False):
    """加载特定前缀的模式数据"""
    if compressed:
        filename = prefix_to_filename_gz(prefix)
        filepath = os.path.join(patterns_dir, filename)
        with gzip.open(filepath, 'rb') as f:
            return pickle.load(f)
    else:
        filename = prefix_to_filename(prefix)
        filepath = os.path.join(patterns_dir, filename)
        with open(filepath, 'rb') as f:
            return pickle.load(f)

def get_addresses_by_pattern(prefix, pattern_str, patterns_dir, compressed=False):
    """根据模式字符串获取对应的所有地址"""
    data = load_prefix_patterns(prefix, patterns_dir, compressed)
    for p in data['patterns']:
        if p['pattern_with_fixed'] == pattern_str:
            return p['addresses']
    return []

def get_all_prefixes(patterns_dir):
    """获取所有已处理的前缀列表"""
    prefixes = []
    for filename in os.listdir(patterns_dir):
        if filename.endswith('_patterns.pkl') or filename.endswith('_patterns.pkl.gz'):
            base = filename.replace('_patterns.pkl', '').replace('.gz', '')
            parts = base.split('_')
            if len(parts) >= 2:
                addr_part = ':'.join(parts[:-1])
                prefix_len = parts[-1]
                prefix = f"{addr_part}::/{prefix_len}"
                prefixes.append(prefix)
    return prefixes

# ==================== 程序入口 ====================

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(130)
    except Exception as e:
        print(f"\n未预期的错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)