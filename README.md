# 6Migrate
6Migrate is an IPv6 target generation technology based on address pattern migration, designed for discovering active addresses in seedless prefixes. This technology operates on GNU/Linux and integrates with ZMap for high-speed scanning. Through address pattern migration, 6Migrate can discover IPv6 addresses within prefixes that lack seed addresses. The technology consists of four core modules: address pattern mining, BGP-based prefix association, address pattern migration, and a complete scheduler for multi-round exploration and exploitation.

## Features
- **Pattern Mining**: Extract hierarchical patterns from seed addresses.
- **BGP-Based Prefix Association**: Associates non-seed prefixes with seed prefixes using BGP features.
- **Address Pattern Migration**: Migrate address patterns from seed to non-seed prefixes.
- **Multi-round Scheduling**: Automate exploration and exploitation phases with adjustable budgets.
- **ZMap Integration**: Direct integration with ZMap for high-speed scanning.

## Using 6Migrate
### Quick Start
Run the complete multi-round scheduler:

`python run.py --rounds 3 --seed-addr data/seed/prefix_ip.pkl --seed-prefix data/seed/prefix_seed --noseed-prefix data/noseed/prefix_noseed_noalias --bgp-data data/bgp/rib_20260214 --output-dir output --rate 10000 --budget 10000000`

### Parameter Description
--rounds	Number of scanning iterations (default: 3)
--seed-addr	Seed address file (pkl format with prefix→address mapping)
--seed-prefix	Seed prefix list file
--noseed-prefix	Non-seed prefix list file
--bgp-data	BGP RIB data file
--output-dir	Output directory (default: output)
--port	Port to scan (default: 443)
--rate	ZMap send rate in pps (default: 10000)
--budget	Number of target addresses per round (default: 10000000)

### Module Descriptions
1. Pattern Mining (pattern_mine.py)
Extracts address patterns from seed addresses:

`python modules/pattern_mine.py --input data/seed/prefix_ip.pkl --output-dir output/round_1/patterns --min-length 5`

2. Prefix Association (prefix_association.py)
Associates non-seed prefixes with seed prefixes using BGP features:

`python modules/prefix_association.py --seed data/seed/prefix_seed --noseed data/noseed/prefix_noseed_noalias --bgp data/bgp/rib_20260214 --output output/round_1/associations.txt --clusters 50 --topk 15`

3. Pattern Migration (pattern_migration.py)
Migrates patterns from seed prefixes to non-seed prefixes:

`python modules/pattern_migration.py --patterns-dir output/round_1/patterns --associations output/round_1/associations.txt --output output/round_1/targets_explore.txt --topk 5`

4. High-Performance Generation (pattern_remine.py)
Mines patterns from accumulated active addresses and generates new targets:

`python modules/pattern_remine.py --addr-file output/round_1/active.txt --prefix-file data/noseed/prefix_noseed_noalias --output output/round_2/targets_exploit.txt --total 5000000 --processes 4`
