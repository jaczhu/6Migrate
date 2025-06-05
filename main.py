# from select import select
import time
import subprocess
import argparse
import radix
import random
import math
import ipaddress
import threading
from IPy import IP
from collections import defaultdict, Counter

target_addrs = set()
target_addrs1 = set()
target_addrs2 = set()
target_addrs3 = set()
active_addrs = set()
active_addrs1 = set()
active_addrs2 = set()
active_addrs3 = set()

def writeFile(target, active, targetfile, activefile,mode=False):
    if mode:
        with open(targetfile, 'a+') as f:
            for addr in target:
                f.write(addr+'\n')

    with open(activefile, 'a+') as f:
        for addr in active:
            f.write(addr+'\n')


def Scan(target_file, source_ip, tid, epoch):
    scan_output = 'output/scan_output_{}_epoch{}.txt'.format(tid, epoch)

    active_addrs = set()
    command = 'sudo zmap --ipv6-source-ip={} --ipv6-target-file={} -M icmp6_echoscan -r 10000 -q -o {}'\
        .format(source_ip, target_file, scan_output)
    print('[+]prefix noseed{} epoch{} Scanning addresses...'.format(tid, epoch))
    p = subprocess.Popen(command, shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # ret = p.poll()
    while p.poll() == None:
        pass

    if p.poll() == 0:
        for line in open(scan_output):
            if line != '':
                active_addrs.add(line[0:len(line) - 1])
    print('[+]prefix noseed{} epoch{} Scanning finished!'.format(tid, epoch))
    return active_addrs

def calculate_entropy(character_counts):  
    total = sum(character_counts.values())  
    if total == 0:  
        return 0  
    entropy = 0  
    for count in character_counts.values():  
        probability = count / total  
        entropy -= probability * math.log2(probability)  
    return entropy  

def group_by_chars(strings, indices, fix_str, thre):  
    if not indices:  
        # 如果没有更多的索引需要分组，就返回当前字符串列表  
        return {fix_str: strings}  
    # 取出第一个索引，并对字符串列表进行分组  
    first_index = indices[0]
    groups = defaultdict(set)
    for s in strings:
        fix_str_new = fix_str[:first_index] + s[first_index] + fix_str[first_index+1:]
        groups[fix_str_new].add(s)
    # 递归地对每个分组进行进一步分组
    result = defaultdict(set)
    for key, sublist in groups.items():
        if len(sublist) <= thre:
            result[key] = sublist
            continue
        else:
            subgroups = group_by_chars(sublist, indices[1:], key)
            for subgroup_key, subgroup_value in subgroups.items():
                result[subgroup_key] = subgroup_value
    return result

def pattern_generate1(prefix_ip):
    start = time.time()
    prefix_pattern = defaultdict(set)
    print("generating pattern1")
    for prefix, ips in prefix_ip.items():
        length = int(prefix.split('/')[1])
        if length < 33:
            continue
        prefix32 = IP(prefix.split('/')[0]).strFullsize()[:9]
        for ip in ips:
            prefix_pattern[(prefix32, length)].add(ip)
    end = time.time()
    print("pattern1 generating time:", end - start)
    return prefix_pattern

def pattern_generate2(addr_file):
    start = time.time()
    prefix_pattern2 = defaultdict(set)
    print("generating pattern2")
    with open(addr_file, 'r') as f:
        for line in f:
            addr = line.strip()
            prefix32 = IP(addr).strFullsize()[:9]
            prefix_pattern2[prefix32].add(addr)
    end = time.time()
    print("pattern2 generating time:", end - start)
    return prefix_pattern2

def addr_match(prefix_file, addr_file):
    start = time.time()
    prefixes = set()
    #prefix_noseed = set()
    ip6Rtree = radix.Radix()
    prefix_ip = defaultdict(list)
    with open(prefix_file, 'r') as f:
        for line in f:
            ip6Rtree.add(line.strip())
            prefixes.add(line.strip())
    with open(addr_file, 'r') as f:
        for line in f:
            ip = line.strip()
            node = ip6Rtree.search_best(ip)
            if (node == None):
                continue
            prefix_ip[node.prefix].append(ip)
            node = ip6Rtree.search_worst(ip)
            if (node == None):
                continue
            prefix_ip[node.prefix].append(ip)
    #prefix_noseed = prefixes - set(prefix_ip.keys())
    end = time.time()
    print("addr matching time:", end - start)
    return prefix_ip

def replace_stars(s, index=0):
    # 如果已经处理完所有字符，返回当前字符串
    if index == len(s):
        return [s]
    
    # 如果当前字符不是 '*', 递归处理下一个字符
    if s[index] != '*':
        return replace_stars(s, index + 1)
    
    # 如果当前字符是 '*', 替换为 '0' 到 'f' 的所有可能值
    result = []
    for char in '0123456789abcdef':
        # 替换当前 '*' 为 char，并递归处理下一个字符
        new_s = s[:index] + char + s[index + 1:]
        result.extend(replace_stars(new_s, index + 1))
    
    return result

def target_gene(active_addr, prefix_noseed, ipv6, thre, id):
    ip6Rtree = radix.Radix()
    prefix_ip = defaultdict(set)
    pattern_addr = defaultdict(set)
    target_addr = set()
    hex_chars = "0123456789abcdef"
    for prefix in prefix_noseed:
        ip6Rtree.add(prefix)
    for addr in active_addr:
        node = ip6Rtree.search_best(addr)
        if (node != None):
            prefix_ip[node.prefix].add(addr)
    for key, value in prefix_ip.items():
        if len(value) < 3:
            continue
        full_ips = set()
        position_counters = {i: Counter() for i in range(32)}
        for addr in value:
            full_ip = IP(addr).strFullsize().replace(":", "")
            full_ips.add(full_ip)
            for i, char in enumerate(full_ip): 
                position_counters[i][char] += 1
        entropies = {}
        fix_str = '*' * 32 
        for i in range(32):
            character_counts = position_counters[i]
            entropy = calculate_entropy(character_counts)
            if entropy == 0:
                    fix_str=fix_str[:i] + full_ip[i] + fix_str[i+1:]
            entropies[i] = entropy
        sorted_entropy = sorted(entropies.items(), key=lambda x: x[1]) 
        indexes = []
        for index, value in sorted_entropy:
            if value == 0:
                continue
            indexes.append(index)
        result = group_by_chars(full_ips, indexes, fix_str, thre)
        for key2, value2 in result.items():
            pattern_addr[key2].add(value2)
    for pattern, addrs in pattern_addr.items():
        star_positions = [pos for pos, char in enumerate(pattern) if char == '*']
        if len(star_positions) == 1:
            for char in hex_chars:
                new_addr = pattern.replace('*', char, 1)
                if new_addr not in addrs:
                    new_ip = str(IP(':'.join(new_addr[i:i+4] for i in range(0, 32, 4))))
                    target_addr.add(new_ip)
        else:
            for index in star_positions:
                is_fix = True
                addr_list = list(addrs)
                reference_char = addr_list[0][index]
                for addr in addr_list[1:]:
                    if addr[index] != reference_char:
                        is_fix = False
                        break
                if is_fix:
                    pattern = pattern[:index] + reference_char + pattern[index + 1:]
                    break
            result = replace_stars(pattern)
            for ip in result:
                if ip not in addrs:
                    new_ip = str(IP(':'.join(ip[i:i+4] for i in range(0, 32, 4))))
                    target_addr.add(new_ip)
    target_file = 'output/target_noseed{}_gene'.format(id)
    with open(target_file, 'w') as f:
        for addr in target_addr:
            f.write(addr + '\n')
    active_addr = Scan(target_file, ipv6, id, 2)
    return target_addr, active_addr

def process_prefix_noseed1(args, prefix_noseed, prefix_noseed1, prefix_pattern, id = 1):
    global target_addrs1, active_addrs1
    print("processing prefix_noseed1...")
    print("length of prefix_noseed1 is ", len(prefix_noseed1))
    ipv6 = args.IPv6
    #scanned_target = defaultdict(set)
    target_addrs1 = set()
    for i in range(args.epoch):
        print("prefix_noseed1--epoch", i)
        count1 = 0
        #prefix_target = defaultdict(set)
        target_file = 'output/target_noseed1_epoch{}'.format(i)
        for prefix in prefix_noseed1:
            count1 += 1
            if count1 % 10000 == 0:
                print("prefix_noseed1 count1:", count1)
            length = int(prefix.split('/')[1])
            prefix32 = IP(prefix.split('/')[0]).strFullsize()[:9]
            prefix_mask = (1 << length) - 1
            addr_mask = (1 << (128 - length)) - 1
            prefix_int = int(ipaddress.IPv6Address(prefix.split('/')[0]))
            prefix_part = prefix_int & (prefix_mask << (128 - length))
            #prefix_part = IP(prefix.split('/')[0]).strFullsize().replace(":", "")[:length//4]
            addr_set = prefix_pattern[(prefix32, length)]
            network = ipaddress.IPv6Network(prefix)
            if i == 0:
                for subnet in network.subnets(new_prefix = length + 4):
                    target_addrs1.add(str(subnet).split('/')[0] + '1')
            if len(addr_set) > 500:
                sample_addr = random.sample(addr_set, 500)
            else:
                sample_addr = addr_set
            for addr in sample_addr:
                addr_int = int(ipaddress.IPv6Address(addr))
                addr_part = addr_int & addr_mask
                new_addr_int = prefix_part | addr_part
                new_addr = str(ipaddress.IPv6Address(new_addr_int))
                target_addrs1.add(new_addr)
        print("prefix_noseed1 generating targets:", len(target_addrs1))
        with open(target_file, 'w') as f:
            for addr in target_addrs1:
                f.write(addr + '\n')
        active_addr = Scan(target_file, ipv6, id, i)
        active_addrs1.update(active_addr)
    if args.gene == 1:
        print("prefix_noseed1 generating targets!")
        target_addr, active_addr = target_gene(active_addrs1, prefix_noseed, ipv6, args.thre, id)
        target_addrs1.update(target_addr)
        active_addrs1.update(active_addr)

def process_prefix_noseed2(args, prefix_noseed, prefix_noseed2, prefix_pattern2, id = 2):
    global target_addrs2, active_addrs2
    print("processing prefix_noseed2...")
    print("length of prefix_noseed2 is ", len(prefix_noseed2))
    ipv6 = args.IPv6
    target_addrs2 = set()
    for i in range(args.epoch):
        print("prefix_noseed2--epoch", i)
        count1 = 0
        target_file = 'output/target_noseed2_epoch{}'.format(i)
        for prefix in prefix_noseed2:
            count1 += 1
            if count1 % 10000 == 0:
                print("prefix_noseed2 count1:", count1)
            length = int(prefix.split('/')[1])
            prefix32 = IP(prefix.split('/')[0]).strFullsize()[:9]
            prefix_mask = (1 << length) - 1
            addr_mask = (1 << (128 - length)) - 1
            prefix_int = int(ipaddress.IPv6Address(prefix.split('/')[0]))
            prefix_part = prefix_int & (prefix_mask << (128 - length))
            #prefix_part = IP(prefix.split('/')[0]).strFullsize().replace(":", "")[:length//4]
            addr_set = prefix_pattern2[prefix32]
            network = ipaddress.IPv6Network(prefix)
            if i == 0:
                for subnet in network.subnets(new_prefix = length + 4):
                    target_addrs2.add(str(subnet).split('/')[0] + '1')
            if len(addr_set) > 500:
                sample_addr = random.sample(addr_set, 500)
            else:
                sample_addr = addr_set
            for addr in sample_addr:
                addr_int = int(ipaddress.IPv6Address(addr))
                addr_part = addr_int & addr_mask
                new_addr_int = prefix_part | addr_part
                new_addr = str(ipaddress.IPv6Address(new_addr_int))
                target_addrs2.add(new_addr)
        print("prefix_noseed2 generating targets:", len(target_addrs2))
        with open(target_file, 'w') as f:
            for addr in target_addrs2:
                f.write(addr + '\n')
        active_addr = Scan(target_file, ipv6, id, i)
        active_addrs2.update(active_addr)
    if args.gene == 1:
        print("prefix_noseed2 generating targets!")
        target_addr, active_addr = target_gene(active_addrs2, prefix_noseed, ipv6, args.thre, id)
        target_addrs2.update(target_addr)
        active_addrs2.update(active_addr)

def process_prefix_noseed3(args, prefix_noseed, prefix_noseed3, prefix_pattern2, id = 3):
    global target_addrs3, active_addrs3
    print("processing prefix_noseed3...")
    print("length of prefix_noseed3 is ", len(prefix_noseed3))
    ipv6 = args.IPv6
    target_addrs3 = set()
    for i in range(args.epoch):
        print("prefix_noseed3--epoch", i)
        count1 = 0
        target_file = 'output/target_noseed3_epoch{}'.format(i)
        for prefix in prefix_noseed3:
            count1 += 1
            if count1 % 10000 == 0:
                print("prefix_noseed3 count1:", count1)
            if i == 0:
                target_addrs3.add(prefix.split('/')[0] + '1')
            length = int(prefix.split('/')[1])
            addr_mask = (1 << (128 - length)) - 1
            prefix_mask = (1 << length) - 1
            prefix_int = int(ipaddress.IPv6Address(prefix.split('/')[0]))
            prefix_part = prefix_int & (prefix_mask << (128 - length))
            network = ipaddress.IPv6Network(prefix)
            if i == 0:
                for subnet in network.subnets(new_prefix = length + 4):
                    target_addrs3.add(str(subnet).split('/')[0] + '1')
            count2 = 0
            for _, value in prefix_pattern2.items():
                count2 += 1
                if count2 == 20:
                    break
                if len(value) > 20:
                    sample_addr = random.sample(value, 20)
                else:
                    sample_addr = value
                for addr in sample_addr:
                    addr_int = int(ipaddress.IPv6Address(addr))
                    addr_part = addr_int & addr_mask
                    new_addr_int = prefix_part | addr_part
                    new_addr = str(ipaddress.IPv6Address(new_addr_int))
                    target_addrs3.add(new_addr)
        print("prefix_noseed3 generating targets:", len(target_addrs3))
        with open(target_file, 'w') as f:
            for addr in target_addrs3:
                f.write(addr + '\n')
        active_addr = Scan(target_file, ipv6, id, i)
        active_addrs3.update(active_addr)
    if args.gene == 1:
        print("prefix_noseed3 generating targets!")
        target_addr, active_addr = target_gene(active_addrs3, prefix_noseed, ipv6, args.thre, id)
        target_addrs3.update(target_addr)
        active_addrs3.update(active_addr)

if __name__ == "__main__":
    parse=argparse.ArgumentParser()
    parse.add_argument('--addr_file', type=str, help='path of seed addresses')
    parse.add_argument('--prefix_file', type=str, help='path of prefixes')
    parse.add_argument('--prefix_noseed', type=str, help='path of non-seed prefixes')
    parse.add_argument('--IPv6',type=str,help='local IPv6 address')
    parse.add_argument('--budget',type=int,help='quantity of addresses detected by each BGP')
    parse.add_argument('--epoch',type=int, default=2, help='number of dynamic scan rounds')
    parse.add_argument('--thre',type=int, default=2, help='threshold of number of target addresses to split')
    parse.add_argument('--gene',type=int, default=0, help='whether to generate targets')
    args=parse.parse_args()
    start_time = time.time()
    prefix_noseed = set()
    prefix_noseed1 = set()
    prefix_noseed2 = set()
    prefix_noseed3 = set()
    # 生成模式
    prefix_ip = addr_match(args.prefix_file, args.addr_file)
    print('length of prefix_ip: {}'.format(len(prefix_ip)))
    prefix_pattern1 = pattern_generate1(prefix_ip)
    print('length of prefix_pattern1: {}'.format(len(prefix_pattern1)))
    prefix_pattern2 = pattern_generate2(args.addr_file)
    prefix_pattern3 = prefix_pattern2
    with open(args.prefix_noseed, 'r') as f:
        for line in f:
            prefix_noseed.add(line.strip())
    for prefix in prefix_noseed:
        length = int(prefix.split('/')[1])
        if length > 32:
            prefix32 = IP(prefix.split('/')[0]).strFullsize()[:9]
            if (prefix32, length) in prefix_pattern1:
                prefix_noseed1.add(prefix)
            elif prefix32 in prefix_pattern2:
                prefix_noseed2.add(prefix)
            else:
                prefix_noseed3.add(prefix)
        else:
            prefix_noseed3.add(prefix)
    threads = [
        threading.Thread(target=process_prefix_noseed1, args=(args, prefix_noseed, prefix_noseed1, prefix_pattern1, 1)),
        threading.Thread(target=process_prefix_noseed2, args=(args, prefix_noseed, prefix_noseed2, prefix_pattern2, 2)),
        threading.Thread(target=process_prefix_noseed3, args=(args, prefix_noseed, prefix_noseed3, prefix_pattern3, 3))
    ]
    for thread in threads:
        thread.start()
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    active_addrs = active_addrs1.union(active_addrs2, active_addrs3)
    target_addrs = target_addrs1.union(target_addrs2, target_addrs3)
    print('number of active addrs:', len(active_addrs))
    print('number of sent packets:', len(target_addrs))
    hitrate = (len(active_addrs) / len(target_addrs) * 100) if target_addrs else 0
    print(f"hitrate: {hitrate:.2f}%")
    end_time = time.time()
    print("time overhead(s): ", end_time - start_time)
    with open('active_addrs', 'w') as f:
        for addr in active_addrs:
            f.write(addr + '\n')

