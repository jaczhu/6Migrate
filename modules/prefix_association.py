#!/usr/bin/env python3
"""
6Migrate: 基于BGP特征的IPv6地址前缀关联
输入: 种子前缀文件, 非种子前缀文件, BGP数据文件
输出: 每个非种子前缀关联的种子前缀列表
"""

import re
import pickle
import gzip
from collections import defaultdict, Counter
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import os
import sys
from tqdm import tqdm
import argparse  # 新增

# ==================== 移除硬编码全局变量 ====================
# 以下变量将被命令行参数替代
# SEED_PREFIXES_FILE = "../prefix_seed"
# NOSEED_PREFIXES_FILE = "../prefix_noseed_noalias"
# BGP_DATA_FILE = "../rib_20260214"
# OUTPUT_FILE = "output/prefix_associations.txt"
# CLUSTER_MODEL_FILE = "output/kmeans_model.pkl"
# SCALER_FILE = "scaler.pkl"
# FEATURE_KEYS = ['origin_as', 'path_len_avg', 'community_cnt', 'path_diversity', 'peer_diversity']
# N_CLUSTERS = 50
# TOP_K_SEEDS = 15
# USE_SAVED_MODEL = True

# ==================== 保留但移动到函数内部的常量 ====================
FEATURE_KEYS = ['origin_as', 'path_len_avg', 'community_cnt', 'path_diversity', 'peer_diversity']

# ==================== 新增：参数解析函数 ====================
def parse_arguments():
    """解析命令行参数（极简版）"""
    parser = argparse.ArgumentParser(
        description='IPv6地址前缀关联工具',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--seed', '-s', required=True,
                        help='种子前缀文件')
    parser.add_argument('--noseed', '-n', required=True,
                        help='无种子前缀文件')
    parser.add_argument('--bgp', '-b', required=True,
                        help='BGP数据文件')
    parser.add_argument('--output', '-o', required=True,
                        help='输出关联文件')
    parser.add_argument('--model', '-m',
                        default='kmeans_model.pkl',
                        help='K-Means模型保存路径 (默认: kmeans_model.pkl)')
    parser.add_argument('--clusters', '-c',
                        type=int, default=50,
                        help='聚类数量 (默认: 50)')
    parser.add_argument('--topk', '-k',
                        type=int, default=15,
                        help='每个无种子前缀关联的种子数量 (默认: 15)')
    parser.add_argument('--no-save-model',
                        action='store_true',
                        help='不保存模型')
    parser.add_argument('--force-retrain',
                        action='store_true',
                        help='强制重新训练，不使用已有模型')
    
    return parser.parse_args()

# ==================== BGP数据解析器（完全不变） ====================
class BGPParser:
    """流式解析BGP数据文件"""
    
    def __init__(self, filename):
        self.filename = filename
        self.prefix_features = {}
        self.prefix_entries = defaultdict(list)
        
    def parse(self, target_prefixes=None):
        """解析BGP文件，提取目标前缀的特征"""
        print(f"开始解析BGP文件: {self.filename}")
        
        opener = gzip.open if self.filename.endswith('.gz') else open
        mode = 'rt' if self.filename.endswith('.gz') else 'r'
        
        entry_count = 0
        matched_count = 0
        
        with opener(self.filename, mode, encoding='utf-8') as f:
            content = f.read()
        
        entries = content.strip().split('\n\n')
        total_entries = len(entries)
        
        print(f"发现 {total_entries} 个BGP条目")
        
        for entry in tqdm(entries, desc="解析BGP条目"):
            if not entry.strip():
                continue
            
            entry_count += 1
            self._parse_entry(entry, target_prefixes)
            
            if entry_count % 10000 == 0 and matched_count > 0:
                print(f"  已解析 {entry_count} 条目，匹配 {matched_count} 个前缀")
        
        print(f"解析完成，共匹配 {len(self.prefix_features)} 个前缀")
        return self.prefix_features
    
    def _parse_entry(self, entry_text, target_prefixes):
        """解析单个BGP条目"""
        lines = entry_text.strip().split('\n')
        
        prefix = None
        from_as = None
        as_path = None
        communities = []
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('PREFIX:'):
                prefix = line.replace('PREFIX:', '').strip()
                if target_prefixes and prefix not in target_prefixes:
                    return
                
            elif line.startswith('FROM:'):
                match = re.search(r'AS(\d+)', line)
                if match:
                    from_as = match.group(1)
                    
            elif line.startswith('ASPATH:'):
                as_path = line.replace('ASPATH:', '').strip()
                
            elif line.startswith('COMMUNITY:'):
                comm_str = line.replace('COMMUNITY:', '').strip()
                if comm_str and comm_str != '[]':
                    communities = comm_str.split()
        
        if not prefix or not as_path:
            return
        
        as_path_list = as_path.split()
        origin_as = as_path_list[-1] if as_path_list else None
        
        if origin_as:
            origin_as = re.sub(r'[^\d]', '', origin_as)
            if not origin_as:
                origin_as = None

        entry_info = {
            'from_as': from_as,
            'as_path': as_path,
            'as_path_length': len(as_path_list),
            'origin_as': origin_as,
            'communities': communities,
        }
        
        self.prefix_entries[prefix].append(entry_info)

# ==================== 特征提取器（完全不变） ====================
class FeatureExtractor:
    """从BGP条目中提取每个前缀的5维特征"""
    
    def __init__(self, prefix_entries):
        self.prefix_entries = prefix_entries
        self.features = {}
        
    def extract_all(self):
        """为所有前缀提取特征"""
        print("\n提取BGP特征...")
        
        for prefix, entries in tqdm(self.prefix_entries.items(), desc="提取特征"):
            self.features[prefix] = self._extract_for_prefix(entries)
        
        return self.features
    
    def _extract_for_prefix(self, entries):
        """为单个前缀提取特征"""
        origin_counts = Counter()
        as_path_lengths = []
        all_communities = set()
        all_peers = set()
        all_as_paths = set()
        
        for entry in entries:
            if entry['origin_as']:
                origin_counts[str(entry['origin_as'])] += 1
            
            as_path_lengths.append(entry['as_path_length'])
            all_as_paths.add(entry['as_path'])
            
            if entry['communities']:
                all_communities.update(entry['communities'])
            
            if entry['from_as']:
                all_peers.add(entry['from_as'])
        
        origin_as = origin_counts.most_common(1)[0][0] if origin_counts else '0'
        path_len_avg = np.mean(as_path_lengths) if as_path_lengths else 0
        community_cnt = len(all_communities)
        path_diversity = len(all_as_paths)
        peer_diversity = len(all_peers)
        
        return {
            'origin_as': origin_as,
            'path_len_avg': round(path_len_avg, 2),
            'community_cnt': community_cnt,
            'path_diversity': path_diversity,
            'peer_diversity': peer_diversity
        }

# ==================== 两阶段关联器（小修改：参数化） ====================
class PrefixAssociator:
    """两阶段前缀关联器"""
    
    def __init__(self, seed_features, noseed_features, 
                 n_clusters=50, top_k=5, 
                 model_file=None, force_retrain=False):
        """
        Args:
            seed_features: 种子前缀特征
            noseed_features: 非种子前缀特征
            n_clusters: 聚类数
            top_k: 每个非种子前缀关联的种子数量
            model_file: 模型文件路径
            force_retrain: 是否强制重新训练
        """
        self.seed_features = seed_features
        self.noseed_features = noseed_features
        self.n_clusters = n_clusters
        self.top_k = top_k
        self.model_file = model_file
        self.force_retrain = force_retrain
        
        self.seed_prefixes = list(seed_features.keys())
        self.seed_as_set = set(f['origin_as'] for f in seed_features.values())
        
        self.as_to_seeds = defaultdict(list)
        for prefix, feat in seed_features.items():
            self.as_to_seeds[feat['origin_as']].append(prefix)
        
        self.associations = {}
        
    def associate(self):
        """执行两阶段关联"""
        print("\n开始两阶段关联...")
        
        stage1_count = 0
        stage2_count = 0
        
        # 第一阶段：AS匹配
        print("\n第一阶段：AS匹配")
        for noseed, feat in tqdm(self.noseed_features.items(), desc="AS匹配"):
            asn = feat['origin_as']
            if asn in self.as_to_seeds:
                seeds = self.as_to_seeds[asn]
                self.associations[noseed] = [(s, 1.0, 'AS') for s in seeds[:self.top_k]]
                stage1_count += 1
        
        print(f"AS匹配完成: {stage1_count} 个前缀")
        
        unmatched_noseeds = [p for p in self.noseed_features if p not in self.associations]
        
        if unmatched_noseeds:
            print(f"\n第二阶段：BGP特征匹配 ({len(unmatched_noseeds)} 个前缀)")
            self._stage2_clustering(unmatched_noseeds)
            stage2_count = len(unmatched_noseeds)
        
        print(f"\n关联完成: AS匹配={stage1_count}, BGP匹配={stage2_count}, 总计={len(self.associations)}")
        
        return self.associations
    
    def _stage2_clustering(self, unmatched_noseeds):
        """第二阶段聚类"""
        # 检查是否可以使用已保存的模型
        use_saved = (not self.force_retrain) and self.model_file and os.path.exists(self.model_file)
        
        if use_saved:
            try:
                print(f"  尝试加载已保存的模型: {self.model_file}")
                with open(self.model_file, 'rb') as f:
                    loaded_model = pickle.load(f)
                kmeans = loaded_model['kmeans']
                scaler = loaded_model['scaler']
                cluster_to_seeds = loaded_model['cluster_to_seeds']
                print(f"  成功加载模型")
            except Exception as e:
                print(f"  加载模型失败: {e}，重新训练")
                use_saved = False
        
        if not use_saved:
            print(f"  训练K-Means模型 (聚类数={self.n_clusters})...")
            
            seed_feat_matrix = []
            seed_prefix_list = []
            
            for prefix in self.seed_prefixes:
                feat = self.seed_features[prefix]
                as_val = float(feat['origin_as']) if feat['origin_as'].isdigit() else 0.0
                vec = [
                    as_val,
                    feat['path_len_avg'],
                    feat['community_cnt'],
                    feat['path_diversity'],
                    feat['peer_diversity']
                ]
                seed_feat_matrix.append(vec)
                seed_prefix_list.append(prefix)
            
            seed_feat_matrix = np.array(seed_feat_matrix)
            
            scaler = StandardScaler()
            seed_feat_scaled = scaler.fit_transform(seed_feat_matrix)
            
            kmeans = KMeans(n_clusters=self.n_clusters, random_state=42, n_init=10)
            cluster_labels = kmeans.fit_predict(seed_feat_scaled)
            
            cluster_to_seeds = defaultdict(list)
            for prefix, label in zip(seed_prefix_list, cluster_labels):
                cluster_to_seeds[label].append(prefix)
            
            # 保存模型（除非指定不保存）
            if self.model_file and not self.force_retrain:
                os.makedirs(os.path.dirname(self.model_file) or '.', exist_ok=True)
                with open(self.model_file, 'wb') as f:
                    pickle.dump({
                        'kmeans': kmeans,
                        'scaler': scaler,
                        'cluster_to_seeds': cluster_to_seeds
                    }, f)
                print(f"  模型已保存到 {self.model_file}")
        
        print(f"  为 {len(unmatched_noseeds)} 个非种子前缀找最近簇...")
        
        for noseed in tqdm(unmatched_noseeds, desc="特征匹配"):
            feat = self.noseed_features[noseed]
            vec = np.array([[
                float(feat['origin_as']) if feat['origin_as'].isdigit() else 0.0,
                feat['path_len_avg'],
                feat['community_cnt'],
                feat['path_diversity'],
                feat['peer_diversity']
            ]])
            
            vec_scaled = scaler.transform(vec)
            distances = np.linalg.norm(kmeans.cluster_centers_ - vec_scaled, axis=1)
            nearest_cluster = np.argmin(distances)
            similarity = 1.0 / (1.0 + distances[nearest_cluster])
            
            seeds_in_cluster = cluster_to_seeds[nearest_cluster]
            import random
            selected = random.sample(seeds_in_cluster, min(self.top_k, len(seeds_in_cluster)))
            
            self.associations[noseed] = [(s, similarity, 'BGP') for s in selected]

# ==================== 工具函数 ====================
def load_prefixes(filename):
    """加载前缀文件"""
    with open(filename, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_associations(associations, filename):
    """保存关联结果"""
    os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("# noseed_prefix\tseed_prefix\tsimilarity\tmethod\n")
        for noseed, seeds in associations.items():
            for seed, sim, method in seeds:
                f.write(f"{noseed}\t{seed}\t{sim:.4f}\t{method}\n")
    print(f"\n关联结果已保存到 {filename}")

def get_model_path(model_arg, output_file):
    """确保模型文件保存在输出文件同目录"""
    if not model_arg:
        return None
    output_dir = os.path.dirname(output_file)
    if output_dir:
        return os.path.join(output_dir, os.path.basename(model_arg))
    return model_arg

# ==================== 主函数（完全重构） ====================
def main():
    """主函数（极简版）"""
    # 1. 解析参数
    args = parse_arguments()
    
    # 2. 显示配置
    print("="*60)
    print("6Migrate: 基于BGP特征的地址前缀关联")
    print("="*60)
    print(f"种子前缀: {args.seed}")
    print(f"无种子前缀: {args.noseed}")
    print(f"BGP数据: {args.bgp}")
    print(f"输出文件: {args.output}")
    print(f"聚类数: {args.clusters}")
    print(f"关联种子数: {args.topk}")
    print("="*60)
    
    # 3. 加载前缀文件
    print("\n1. 加载前缀文件...")
    seed_prefixes = load_prefixes(args.seed)
    noseed_prefixes = load_prefixes(args.noseed)
    
    print(f"   种子前缀数: {len(seed_prefixes)}")
    print(f"   非种子前缀数: {len(noseed_prefixes)}")
    
    # 4. 解析BGP数据
    print("\n2. 解析BGP数据...")
    all_target_prefixes = seed_prefixes | noseed_prefixes
    parser = BGPParser(args.bgp)
    parser.parse(target_prefixes=all_target_prefixes)
    
    # 5. 提取特征
    extractor = FeatureExtractor(parser.prefix_entries)
    all_features = extractor.extract_all()
    
    # 6. 分离种子和非种子特征
    seed_features = {p: all_features[p] for p in seed_prefixes if p in all_features}
    noseed_features = {p: all_features[p] for p in noseed_prefixes if p in all_features}
    
    print(f"\n   有BGP特征的种子前缀: {len(seed_features)}/{len(seed_prefixes)}")
    print(f"   有BGP特征的非种子前缀: {len(noseed_features)}/{len(noseed_prefixes)}")
    
    # 7. 如果没有任何特征，退出
    if not seed_features or not noseed_features:
        print("错误: 没有足够的BGP特征数据进行关联")
        return 1
    
    # 8. 执行关联
    model_file = get_model_path(args.model, args.output) if not args.no_save_model else None
    associator = PrefixAssociator(
        seed_features=seed_features,
        noseed_features=noseed_features,
        n_clusters=args.clusters,
        top_k=args.topk,
        model_file=model_file,
        force_retrain=args.force_retrain
    )
    associations = associator.associate()
    
    # 9. 保存结果
    save_associations(associations, args.output)
    
    print("\n" + "="*60)
    print("关联完成！")
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