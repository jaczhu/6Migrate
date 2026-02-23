#!/usr/bin/env python3
"""
6Migrate-Gen: IPv6地址模式挖掘与生成（高性能版）
针对千万级地址生成优化
"""

import pickle
from collections import defaultdict, Counter
from ipaddress import IPv6Address
import math
import random
import numpy as np
from tqdm import tqdm
import radix
import hashlib
from multiprocessing import Pool, cpu_count
import gc
import os
import sys
import argparse  # 新增

# ==================== 移除硬编码全局变量 ====================
# INPUT_PREFIX_FILE = "../prefix_noseed_noalias"
# INPUT_ADDR_FILE = "output/active_address"
# OUTPUT_FILE = "output/generated_addresses2.txt"
# MIN_PATTERN_LENGTH = 5
# TOTAL_GENERATE = 10000000
# RANDOM_SEED = 42
# MAX_GENERATE_PER_PATTERN = 100000
# BLOOM_FILTER_SIZE = 10_000_000
# NUM_PROCESSES = max(1, cpu_count() - 1)
# BATCH_SIZE = 10000

# ==================== 保留但参数化的变量 ====================
# 这些将在 main 中根据 args 设置

# ==================== 全局缓存（保持不变） ====================
_ADDR_TO_HEX_CACHE = {}
HEX_CHARS = np.array(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'])

# ==================== 新增：参数解析函数 ====================
def parse_arguments():
    """解析命令行参数（极简版）"""
    parser = argparse.ArgumentParser(
        description='IPv6地址高性能生成工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --addr-file output/round_1/active.txt --prefix-file data/noseed/prefix_noseed_noalias --output output/round_2/targets.txt
  %(prog)s -a active.txt -p prefixes.txt -o targets.txt --total 5000000 --processes 4
        """
    )
    
    parser.add_argument('--addr-file', '-a', required=True,
                        help='存活地址文件 (每行一个IPv6地址)')
    
    parser.add_argument('--prefix-file', '-p', required=True,
                        help='无种子前缀文件 (每行一个前缀)')
    
    parser.add_argument('--output', '-o', required=True,
                        help='输出文件路径 (生成的地址列表)')
    
    parser.add_argument('--total', '-t',
                        type=int, default=10000000,
                        help='总共要生成的地址数量 (默认: 10000000)')
    
    parser.add_argument('--min-length', '-m',
                        type=int, default=5,
                        help='最小通配符数量 (默认: 5)')
    
    parser.add_argument('--max-per-pattern',
                        type=int, default=100000,
                        help='每个模式最大生成数量 (默认: 100000)')
    
    parser.add_argument('--seed',
                        type=int, default=42,
                        help='随机种子 (默认: 42)')
    
    parser.add_argument('--processes',
                        type=int, default=max(1, cpu_count() - 1),
                        help='并行进程数 (默认: CPU核心数-1)')
    
    parser.add_argument('--bloom-size',
                        type=int, default=10_000_000,
                        help='布隆过滤器大小 (默认: 10000000)')
    
    parser.add_argument('--no-cache',
                        action='store_true',
                        help='不使用地址转换缓存')
    
    return parser.parse_args()

# ==================== 工具函数（添加缓存控制） ====================

def ipv6_to_hex_array_cached(addr, use_cache=True):
    """带缓存的IPv6地址转换"""
    if not use_cache:
        try:
            ip_int = int(IPv6Address(addr))
            hex_str = f"{ip_int:032x}"
            return list(hex_str)
        except:
            return None
    
    if addr in _ADDR_TO_HEX_CACHE:
        return _ADDR_TO_HEX_CACHE[addr]
    
    try:
        ip_int = int(IPv6Address(addr))
        hex_str = f"{ip_int:032x}"
        result = list(hex_str)
        _ADDR_TO_HEX_CACHE[addr] = result
        return result
    except:
        return None

def hex_array_to_ipv6_fast(hex_array):
    """快速将hex数组转换为IPv6地址"""
    hex_str = ''.join(hex_array)
    return ':'.join(hex_str[i:i+4] for i in range(0, 32, 4))

# ==================== 布隆过滤器（完全不变） ====================
class BloomFilter:
    """简单的布隆过滤器用于快速去重"""
    def __init__(self, size, num_hashes=3):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray(size // 8 + 1)
        self.count = 0
    
    def _hashes(self, item):
        result = []
        for i in range(self.num_hashes):
            h = hashlib.md5(f"{item}{i}".encode()).digest()
            val = int.from_bytes(h[:8], 'little') % self.size
            result.append(val)
        return result
    
    def add(self, item):
        for h in self._hashes(item):
            byte_idx = h // 8
            bit_idx = h % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
        self.count += 1
    
    def contains(self, item):
        for h in self._hashes(item):
            byte_idx = h // 8
            bit_idx = h % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

# ==================== 节点类（完全不变） ====================
class PatternNode:
    __slots__ = ('addr_indices', 'pattern', 'children', 'is_leaf', 'final_pattern_fixed', 'wildcard_count', 'addr_count')
    
    def __init__(self, addr_indices, pattern=None):
        self.addr_indices = addr_indices
        self.addr_count = len(addr_indices) if addr_indices is not None else 0
        self.pattern = pattern if pattern is not None else ['*'] * 32
        self.wildcard_count = self.pattern.count('*')
        self.children = []
        self.is_leaf = False
        self.final_pattern_fixed = None
    
    def calculate_wildcard_entropy_fast(self, hex_arrays):
        if self.wildcard_count == 0:
            return {}
        
        wildcard_positions = [i for i, ch in enumerate(self.pattern) if ch == '*']
        
        values_at_pos = []
        for pos in wildcard_positions:
            pos_values = [hex_arrays[idx][pos] for idx in self.addr_indices]
            values_at_pos.append(pos_values)
        
        entropies = {}
        for pos_idx, pos in enumerate(wildcard_positions):
            counter = Counter(values_at_pos[pos_idx])
            total = self.addr_count
            e = 0.0
            for count in counter.values():
                p = count / total
                if p > 0:
                    e -= p * math.log2(p)
            entropies[pos] = e
        
        return entropies
    
    def split_fast(self, split_pos, hex_arrays):
        groups = defaultdict(list)
        
        for idx in self.addr_indices:
            value = hex_arrays[idx][split_pos]
            groups[value].append(idx)
        
        children = []
        for value, indices in groups.items():
            new_pattern = self.pattern.copy()
            new_pattern[split_pos] = value
            children.append(PatternNode(indices, new_pattern))
        
        return children
    
    def mark_leaf(self, hex_arrays):
        self.is_leaf = True
        
        if not hasattr(self, 'addr_count') or self.addr_count == 0:
            self.addr_count = len(self.addr_indices) if self.addr_indices else 0

        new_pattern = self.pattern.copy()
        if self.addr_indices:
            for i, ch in enumerate(self.pattern):
                if ch == '*':
                    first_val = hex_arrays[self.addr_indices[0]][i]
                    all_same = True
                    for idx in self.addr_indices[1:]:
                        if hex_arrays[idx][i] != first_val:
                            all_same = False
                            break
                    if all_same:
                        new_pattern[i] = first_val
        
        self.final_pattern_fixed = ''.join(new_pattern)
        self.addr_indices = None

# ==================== 挖掘器类（小修改：传递min_wildcards） ====================
class PatternMiner:
    def __init__(self, min_wildcards=5):
        self.min_wildcards = min_wildcards
    
    # 在 pattern_remine.py 中修改 PatternMiner 类的 mine_fast 方法

def mine_fast(self, addresses, hex_arrays, disable_progress=True):  # 添加参数
    if len(addresses) < 2:
        pattern_str = addresses[0] if addresses else ""
        return [{
            'pattern': pattern_str,
            'count': len(addresses),
            'wildcards': 0
        }]
    
    addr_indices = list(range(len(addresses)))
    root = PatternNode(addr_indices)
    
    stack = [root]
    leaf_patterns = []
    
    # 修改这里：根据参数控制进度条显示
    with tqdm(total=len(stack), desc="构建树", leave=False, disable=disable_progress) as pbar:
        while stack:
            node = stack.pop()
            
            if not hasattr(node, 'addr_count') or node.addr_count == 0:
                node.addr_count = len(node.addr_indices) if node.addr_indices else 0
            
            if node.wildcard_count < self.min_wildcards:
                node.mark_leaf(hex_arrays)
                leaf_patterns.append({
                    'pattern': node.final_pattern_fixed,
                    'count': node.addr_count,
                    'wildcards': node.wildcard_count
                })
                continue
            
            entropies = node.calculate_wildcard_entropy_fast(hex_arrays)
            if not entropies:
                node.mark_leaf(hex_arrays)
                leaf_patterns.append({
                    'pattern': node.final_pattern_fixed,
                    'count': node.addr_count,
                    'wildcards': node.wildcard_count
                })
                continue
            
            split_pos = min(entropies, key=entropies.get)
            children = node.split_fast(split_pos, hex_arrays)
            
            for child in children:
                stack.append(child)
                pbar.total += 1
            pbar.update(1)
    
    return leaf_patterns

# ==================== 生成器类（小修改：接受seed参数） ====================
class HybridAddressGenerator:
    """混合地址生成器 - 根据通配符数量选择策略"""
    
    def __init__(self, seed=42):
        self.enumerator = PatternEnumerator()
        self.rng = random.Random(seed)
        self.hex_chars = '0123456789abcdef'
        self.sequential_mode_threshold = 4
        self.parallel_threshold = 6
    
    def generate_addresses(self, pattern_info, target_count):
        pattern_str = pattern_info['pattern']
        wildcard_count = pattern_info['wildcards']
        
        if wildcard_count == 0:
            return [pattern_str] if target_count > 0 else []
        
        total_possible = 16 ** wildcard_count
        
        if target_count >= total_possible:
            return self.enumerator.enumerate_pattern(pattern_str)
        
        elif wildcard_count <= self.sequential_mode_threshold:
            return self._sequential_generate(pattern_str, wildcard_count, target_count)
        
        elif wildcard_count <= self.parallel_threshold:
            return self._parallel_enumerate(pattern_str, wildcard_count, target_count)
        
        else:
            return self._random_sample(pattern_str, wildcard_count, target_count)
    
    def _sequential_generate(self, pattern_str, w_count, target_count):
        pattern_array = list(pattern_str)
        wildcard_positions = [i for i, ch in enumerate(pattern_str) if ch == '*']
        
        results = []
        step = max(1, (16 ** w_count) // target_count)
        
        for i in range(0, 16 ** w_count, step):
            if len(results) >= target_count:
                break
            
            temp_array = pattern_array.copy()
            remaining = i
            for pos in reversed(wildcard_positions):
                digit = remaining % 16
                temp_array[pos] = self.hex_chars[digit]
                remaining //= 16
            
            results.append(self._array_to_ipv6(temp_array))
        
        return results
    
    def _parallel_enumerate(self, pattern_str, w_count, target_count):
        import math
        from concurrent.futures import ThreadPoolExecutor
        
        pattern_array = list(pattern_str)
        wildcard_positions = [i for i, ch in enumerate(pattern_str) if ch == '*']
        
        total = 16 ** w_count
        chunk_size = max(1, total // (target_count // 100))
        num_chunks = math.ceil(total / chunk_size)
        
        def generate_chunk(chunk_idx):
            start = chunk_idx * chunk_size
            end = min((chunk_idx + 1) * chunk_size, total)
            
            chunk_results = []
            for i in range(start, end, max(1, (end - start) // (target_count // num_chunks))):
                if len(chunk_results) >= target_count // num_chunks:
                    break
                
                temp_array = pattern_array.copy()
                remaining = i
                for pos in reversed(wildcard_positions):
                    digit = remaining % 16
                    temp_array[pos] = self.hex_chars[digit]
                    remaining //= 16
                
                chunk_results.append(self._array_to_ipv6(temp_array))
            
            return chunk_results
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(generate_chunk, range(num_chunks)))
        
        merged = []
        for chunk in results:
            merged.extend(chunk)
            if len(merged) >= target_count:
                break
        
        return merged[:target_count]
    
    def _random_sample(self, pattern_str, w_count, target_count):
        pattern_array = list(pattern_str)
        wildcard_positions = [i for i, ch in enumerate(pattern_str) if ch == '*']
        
        results = []
        seen = set()
        
        while len(results) < target_count:
            temp_array = pattern_array.copy()
            for pos in wildcard_positions:
                temp_array[pos] = self.hex_chars[self.rng.randint(0, 15)]
            
            addr = self._array_to_ipv6(temp_array)
            if addr not in seen:
                seen.add(addr)
                results.append(addr)
        
        return results
    
    def _array_to_ipv6(self, array):
        hex_str = ''.join(array)
        return ':'.join(hex_str[i:i+4] for i in range(0, 32, 4))
    
    def generate_batch_with_dedup(self, pattern_info, target_count, bloom_filter):
        generated = self.generate_addresses(pattern_info, target_count)
        
        results = []
        added = 0
        for addr in generated:
            if not bloom_filter.contains(addr):
                results.append(addr)
                bloom_filter.add(addr)
                added += 1
                if added >= target_count:
                    break
        
        return results

class PatternEnumerator:
    """模式枚举器 - 遍历通配符所有可能取值"""
    
    def __init__(self):
        self.hex_chars = '0123456789abcdef'
    
    def enumerate_pattern(self, pattern_str, max_count=None):
        pattern_array = list(pattern_str)
        wildcard_positions = [i for i, ch in enumerate(pattern_str) if ch == '*']
        
        if not wildcard_positions:
            return [pattern_str] if max_count != 0 else []
        
        total_combinations = 16 ** len(wildcard_positions)
        
        if max_count and max_count < total_combinations:
            return self._sample_pattern(pattern_array, wildcard_positions, max_count)
        
        return self._generate_all(pattern_array, wildcard_positions)
    
    def _generate_all(self, pattern_array, wildcard_positions):
        if not wildcard_positions:
            return [self._array_to_ipv6(pattern_array)]
        
        results = []
        self._generate_recursive(pattern_array.copy(), wildcard_positions, 0, results)
        return results
    
    def _generate_recursive(self, current_array, positions, idx, results):
        if idx == len(positions):
            results.append(self._array_to_ipv6(current_array))
            return
        
        pos = positions[idx]
        for char in self.hex_chars:
            current_array[pos] = char
            self._generate_recursive(current_array, positions, idx + 1, results)
    
    def _sample_pattern(self, pattern_array, wildcard_positions, sample_size):
        results = []
        total_positions = len(wildcard_positions)
        
        step = max(1, (16 ** total_positions) // sample_size)
        
        for i in range(0, 16 ** total_positions, step):
            if len(results) >= sample_size:
                break
            
            temp_array = pattern_array.copy()
            remaining = i
            for j, pos in enumerate(reversed(wildcard_positions)):
                digit = remaining % 16
                temp_array[pos] = self.hex_chars[digit]
                remaining //= 16
            
            results.append(self._array_to_ipv6(temp_array))
        
        return results
    
    def _array_to_ipv6(self, array):
        hex_str = ''.join(array)
        return ':'.join(hex_str[i:i+4] for i in range(0, 32, 4))

# ==================== 并行处理函数（小修改） ====================

def process_prefix_chunk(args):
    """处理单个前缀（用于并行）"""
    prefix, addresses, min_pattern_length, use_cache = args
    
    hex_arrays = []
    valid_addresses = []
    for addr in addresses:
        ha = ipv6_to_hex_array_cached(addr, use_cache)
        if ha:
            hex_arrays.append(ha)
            valid_addresses.append(addr)
    
    if not valid_addresses:
        return prefix, []
    
    miner = PatternMiner(min_pattern_length)
    # 在并行处理时禁用内部进度条
    patterns = miner.mine_fast(valid_addresses, hex_arrays, disable_progress=True)
    
    return prefix, patterns

def generate_chunk_enumerate(args):
    """使用枚举的生成任务"""
    prefix, patterns, quotas, seed, bloom_size = args
    
    generator = HybridAddressGenerator(seed)
    bloom = BloomFilter(bloom_size)
    
    results = []
    total = 0
    
    for idx, count in quotas[prefix].items():
        if count <= 0 or idx >= len(patterns):
            continue
        
        batch_results = generator.generate_batch_with_dedup(patterns[idx], count, bloom)
        results.extend(batch_results)
        total += len(batch_results)
    
    return prefix, results, total

# ==================== 数据加载函数（修改） ====================

def load_prefixes(filename):
    """加载前缀文件"""
    prefixes = []
    with open(filename, 'r') as f:
        for line in f:
            prefix = line.strip()
            if prefix:
                prefixes.append(prefix)
    return prefixes

def load_addresses(filename):
    """加载地址文件"""
    addresses = []
    with open(filename, 'r') as f:
        for line in tqdm(f, desc="读取地址"):
            line = line.strip()
            if line and not line.startswith('#'):
                addresses.append(line)
    return addresses

def match_addresses_to_prefixes(addresses, prefixes):
    """将地址匹配到前缀"""
    rtree = radix.Radix()
    for prefix in prefixes:
        rtree.add(prefix)
    
    prefix_ip = defaultdict(list)
    for ip in tqdm(addresses, desc="匹配前缀"):
        node = rtree.search_best(ip)
        if node:
            prefix_ip[node.prefix].append(ip)
    
    return prefix_ip

# ==================== 主函数（完全重构） ====================
def main():
    """主函数"""
    # 1. 解析参数
    args = parse_arguments()
    
    # 2. 显示配置
    print("="*60)
    print("6Migrate-Gen: IPv6地址高性能生成")
    print("="*60)
    print(f"地址文件: {args.addr_file}")
    print(f"前缀文件: {args.prefix_file}")
    print(f"输出文件: {args.output}")
    print(f"目标总数: {args.total}")
    print(f"最小通配符: {args.min_length}")
    print(f"进程数: {args.processes}")
    print("="*60)
    
    # 3. 检查文件
    if not os.path.isfile(args.addr_file):
        print(f"错误: 地址文件不存在 - {args.addr_file}")
        return 1
    
    if not os.path.isfile(args.prefix_file):
        print(f"错误: 前缀文件不存在 - {args.prefix_file}")
        return 1
    
    # 4. 创建输出目录
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # 5. 加载数据
    print("\n1. 加载数据...")
    prefixes = load_prefixes(args.prefix_file)
    addresses = load_addresses(args.addr_file)
    
    print(f"   前缀数: {len(prefixes)}")
    print(f"   地址数: {len(addresses)}")
    
    if not addresses:
        print("错误: 没有有效的地址")
        return 1
    
    # 6. 匹配前缀
    print("\n2. 匹配地址到前缀...")
    prefix_ip = match_addresses_to_prefixes(addresses, prefixes)
    
    total_matched = sum(len(v) for v in prefix_ip.values())
    print(f"   匹配成功: {total_matched} 个地址, {len(prefix_ip)} 个前缀")
    
    if not prefix_ip:
        print("错误: 没有地址匹配到任何前缀")
        return 1
    
    # 7. 并行挖掘模式
    print("\n3. 并行挖掘模式...")
    
    tasks = [(p, list(addrs), args.min_length, not args.no_cache) 
             for p, addrs in prefix_ip.items()]
    
    all_patterns = {}
    with Pool(processes=args.processes) as pool:
        results = list(tqdm(
            pool.imap_unordered(process_prefix_chunk, tasks),
            total=len(tasks),
            desc="挖掘模式"
        ))
        for prefix, patterns in results:
            if patterns:
                all_patterns[prefix] = patterns
    
    total_patterns = sum(len(p) for p in all_patterns.values())
    print(f"   发现 {total_patterns} 个模式")
    
    if not all_patterns:
        print("错误: 没有挖掘到任何模式")
        return 1
    
    # 8. 计算配额
    print("\n4. 计算配额...")
    prefix_counts = {p: len(prefix_ip[p]) for p in all_patterns.keys()}
    total_processed = sum(prefix_counts.values())
    
    quotas = {}
    for prefix, patterns in all_patterns.items():
        prefix_quota = int(args.total * prefix_counts[prefix] / total_processed)
        if prefix_quota == 0:
            continue
        
        pattern_quotas = {}
        pattern_counts = [p['count'] for p in patterns]
        total_pattern_count = sum(pattern_counts)
        
        if total_pattern_count == 0:
            continue
        
        for i, pattern in enumerate(patterns):
            if pattern['wildcards'] == 0:
                pattern_quotas[i] = 0
                continue
            
            quota = max(1, int(prefix_quota * pattern['count'] / total_pattern_count))
            pattern_quotas[i] = min(quota, args.max_per_pattern)
        
        if pattern_quotas:
            quotas[prefix] = pattern_quotas
    
    total_quota = sum(sum(q.values()) for q in quotas.values())
    print(f"   计划生成 {total_quota} 个地址")
    
    if not quotas:
        print("错误: 没有可用的配额")
        return 1
    
    # 9. 并行生成地址
    print("\n5. 并行生成地址...")
    
    gen_tasks = []
    for i, (prefix, patterns) in enumerate(all_patterns.items()):
        if prefix in quotas:
            gen_tasks.append((prefix, patterns, quotas, args.seed + i, args.bloom_size))
    
    results = {}
    total_generated = 0
    with Pool(processes=args.processes) as pool:
        gen_results = list(tqdm(
            pool.imap_unordered(generate_chunk_enumerate, gen_tasks),
            total=len(gen_tasks),
            desc="生成地址"
        ))
        for prefix, addrs, count in gen_results:
            if addrs:
                results[prefix] = addrs
                total_generated += count
    
    if total_generated == 0:
        print("警告: 没有生成任何地址")
        return 1
    
    # 10. 保存结果
    print("\n6. 保存结果...")
    with open(args.output, 'w') as f:
        f.write(f"# 6Migrate-Gen 生成的IPv6地址\n")
        f.write(f"# 地址文件: {args.addr_file}\n")
        f.write(f"# 前缀文件: {args.prefix_file}\n")
        f.write(f"# 目标总数: {args.total}\n")
        f.write(f"# 实际生成: {total_generated}\n\n")
        
        buffer = []
        for addrs in results.values():
            buffer.extend(addrs)
            if len(buffer) >= 100000:
                f.write('\n'.join(buffer) + '\n')
                buffer = []
        if buffer:
            f.write('\n'.join(buffer) + '\n')
    
    print(f"\n完成! 共生成了 {total_generated} 个地址")
    print(f"结果保存在: {args.output}")
    
    if not args.no_cache:
        print(f"缓存命中率: 地址转换缓存大小 {len(_ADDR_TO_HEX_CACHE)}")
    
    return 0

# ==================== 程序入口 ====================
if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    
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