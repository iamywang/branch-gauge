# BranchGauge: Modeling and Quantifying Leakage in Randomization-Based Secure Branch Predictors

This work introduces a leakage quantification framework for modeling microarchitectural attacks and quantifying side-channel leakage in randomization-based secure branch predictors during the early design phase.

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/iamywang/branch-gauge/cmake.yml)
![GitHub License](https://img.shields.io/github/license/iamywang/branch-gauge)
![GitHub top language](https://img.shields.io/github/languages/top/iamywang/branch-gauge)
![GitHub repo size](https://img.shields.io/github/repo-size/iamywang/branch-gauge)
![GitHub last commit](https://img.shields.io/github/last-commit/iamywang/branch-gauge)
![GitHub Repo stars](https://img.shields.io/github/stars/iamywang/branch-gauge)
![GitHub forks](https://img.shields.io/github/forks/iamywang/branch-gauge)

## 0x01 Getting Started

### Prerequisites

- CMake
- g++/clang++
- Python 3 with numpy and matplotlib
- (Optional) Docker

### (Recommended) Using Docker

A `Dockerfile` is provided for automatic deployment. You can create a Docker container with all necessary dependencies by following these steps:

1. Install Docker: `sudo apt install docker.io`
2. Clone the repository: `git clone https://github.com/iamywang/branch-gauge.git && cd branch-gauge`
3. Build the Docker image: `docker build -t branch-gauge .`
4. Run and attach to the Docker container: `docker run -it branch-gauge`
5. After you are done, delete the Docker container: `docker ps -a` and `docker rm <CONTAINER_ID>`
6. (Optional) Delete the Docker image: `docker images` and `docker rmi <IMAGE_ID>`

Upon attaching to the container, a `bash` shell will be presented:

```bash
root@6f2f0d4af5ea:/branch-gauge/build# ./branch-gauge
Usage: ./branch-gauge [attack] [max_branches|max_pruning_sizes] [max_repeats]
```

### Step by Step Using CMake

To build and run branch-gauge using `CMake`, follow these steps:

1. Install following packages: `sudo apt-get update && apt-get install -y build-essential cmake gcc g++`
2. Clone the repository: `git clone https://github.com/iamywang/branch-gauge.git && cd branch-gauge`
3. Build the project: `mkdir build && cd build && cmake .. && make`
4. Run the project: `./branch-gauge`

The output should be similar to the following:

```shell
Usage: ./branch-gauge [attack] [max_branches|max_pruning_sizes] [max_repeats]
```

## 0x02 Repository Structure

The repository is structured as follows:

```plaintext
BranchGauge/
├── include/
│   ├── predictors/          # Header files for branch predictors
│   └── utils/               # Definitions of EncryptionKey, ReplacementPolicy, SecurityDomain, and other utility functions
├── attacks/                 # Implementation of reuse-based, prune-based, and occupancy-based attacks
├── exps/                    # Implementation of experiments for reproducing the results in the paper
│   ├── plot/                # Scripts for plotting the figures in the paper
│   └── res/                 # Results of the experiments
├── predictors/              # Implementation of the working principle of branch predictors
├── CMakeLists.txt           # CMake configuration file, with several options to enable/disable features
├── main.cpp                 # Main entry point
├── Dockerfile               # Docker configuration file for automatic deployment
└── README.md                # This file
```

## 0x03 Reproduction

To reproduce the results in the paper, you can run the following experiments in the `exps` directory:

1. Reuse-based attack: `python3 exp1_reuse.py`;
2. Prune-based attack: `python3 exp2_prune.py`;
3. Occupancy-based attack: `python3 exp3_occupancy.py`;
4. Leakage quantification: `python3 exp4_leakage.py`;
5. (Advanced) Run all experiments: `sh run.sh`:

```shell
#!/bin/bash
rm -rf res
mkdir res
python3 exp1_reuse.py & python3 exp2_prune.py & python3 exp3_occupancy.py & python3 exp4_leakage.py
```

This process may take several hours to complete (on my i7-12700, it takes approximately ~100 hours), and the results will be saved in the `exps/res/` directory.

To plot the results, you can run the following scripts in the `exps/plot` directory:

1. Figure 6 (Branch accesses metric for reuse-based attacks): `python3 fig6-reuse-n.py`;
2. Figure 7 (Collision proability metric for reuse-based attacks): `python3 fig7-reuse-pr.py`;
3. Figure 8 (Branch accesses metric for prune-based attacks): `python3 fig8-prune-n.py`;
4. Figure 9 (Collision proability metric for prune-based attacks): `python3 fig9-prune-pr.py`;
5. Figure 10 (Branch accesses metric for occupancy-based PHT attacks): `python3 fig10-pht-occupancy-n.py`;
6. Figure 11 (Branch accesses metric for occupancy-based BTB attacks): `python3 fig11-btb-occupancy-n.py`;
7. Figure 12 (Collision proability metric for occupancy-based PHT attacks): `python3 fig12-pht-occupancy-pr.py`;
8. Figure 13 (Collision proability metric for occupancy-based PHT attacks): `python3 fig13-btb-occupancy-pr.py`;
9. Figure 14 (BTB Leakage quantification under single-secret space): `python3 fig14-leakage-reuse-1.py`;
10. Figure 15 (PHT Leakage quantification under single-secret space): `python3 fig15-leakage-reuse-2.py`;
11. Table 2 (PHT Leakage quantification under multiple-secret space): `python3 tab2-leakage-pht.py`;
12. Table 3 (BTB Leakage quantification under multiple-secret space): `python3 tab3-leakage-btb.py`;
13. (Advanced) Run all plotting scripts: `sh plot.sh`:

```shell
#!/bin/bash
python3 fig6-reuse-n.py
python3 fig7-reuse-pr.py
python3 fig8-btb-prune-n.py
python3 fig9-btb-prune-pr.py
python3 fig10-pht-occupancy-n.py
python3 fig11-btb-occupancy-n.py
python3 fig12-pht-occupancy-pr.py
python3 fig13-btb-occupancy-pr.py
python3 fig14-leakage-reuse-1.py
python3 fig15-leakage-reuse-2.py
python3 tab2-leakage-pht.py
python3 tab3-leakage-btb.py
```

## 0x04 License and Acknowledgement

This project is licensed under the terms of the Apache License 2.0.

```plaintext
Copyright 2025 iamywang

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

We would like to thank the authors of the following projects for their useful tools:

- [Phantom1003/QARMA64](https://github.com/Phantom1003/QARMA64)

We have modified and integrated their tools into our code:

- `include/utils/Qarma64.hpp`
- `include/utils/Qarma64.cpp`

## 0x05 Contact and Citation

If you have any questions, please contact me through [GitHub Issues](https://github.com/iamywang/branch-gauge/issues) or via email at `wangquancheng@whu.edu.cn`.

If our work is useful for your research, please consider citing our paper:

```bibtex
@INPROCEEDINGS{wang2025branchgauge,
  title={{BranchGauge: Modeling and Quantifying Side-Channel Leakage in Randomization-Based Secure Branch Predictors}}, 
  author={Wang, Quancheng and Tang, Ming and Xu, Ke and Wang, Han},
  booktitle={Proceedings of the 20th ACM Asia Conference on Computer and Communications Security (ASIA CCS'25)},
  pages={1265--1279},
  year={2025},
  publisher={ACM}
}
```
