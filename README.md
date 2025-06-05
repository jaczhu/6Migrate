# 6Migrate
6Migrate is an efficient IPv6 target generation framework based on address pattern migration, which is designed for non-seed prefixes. This framework operates on GNU/Linux. Through address pattern migration, 6Route can discover IPv6 addresses within prefixes without seed addresses. 6Route consists of three modules, including address pattern mining, address pattern migration, and dynamic address scanning.

## Using 6Migrate
### Target Generation
Firstly, take the seed addresses, seed prefixes and non-seed prefixes collected from public data sources as input, and run the Python script main.py. The parameter --address_file represents the seed address file, --prefix_file represents the seed prefix file, --prefix_noseed represents the non-seed prefix file, --epoch represents the number of scanning iterations, --thre represents the threshold of number of seed addresses to split a node when mining the address patterns of seed addresses, and --budget represents the number of packets to send.

`python main.py --address_file address.txt --prefix_file prefix_seed.txt --prefix_noseed prefix_noseed.txt --epoch 3 --thre 3 --budget 10000000 `
