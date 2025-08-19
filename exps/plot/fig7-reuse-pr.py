# Copyright 2025 iamywang

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# BranchGauge: Modeling and Quantifying Leakage in Randomization-Based Secure
# Branch Predictors

# author: iamywang
# date: 2024/12/29
# =============================================================================
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42
plt.rcParams['text.usetex'] = True
plt.rcParams['text.latex.preamble'] = r'\usepackage{amsfonts}'
plt.rcParams['font.size'] = 12
# plt.rcParams['font.family'] = 'Arial'

# read file
f = open('../res/exp1_reuse_collision_rate.txt', 'r')
lines = f.readlines()
f.close()

num_repeats = 1000

# parse data to from 21 * 8 to 7 * 8 matrix (10000 to 1000000)
data1 = np.zeros((7, 8)) # pht
data2 = np.zeros((7, 8)) # btb timing
data3 = np.zeros((7, 8)) # btb speculative
for l in range(len(lines)):
    line = lines[l].split(' ') # 21 values
    for i in range(7):
        data1[i][l] = int(line[i])
        data2[i][l] = int(line[i + 7])
        data3[i][l] = int(line[i + 14])

# print the index of the first 90% value
bpu_types = ['Baseline', 'BSUP', 'XOR', 'Noisy-XOR', 'LS-BP', 'STBPU', 'HyBP']
x = [10000, 50000, 100000, 200000, 500000, 1000000, 10000000, 100000000]
print('== PHT Reuse Collision ==')
for i in range(7):
    for l in range(8):
        if (data1[i][l] >= num_repeats * 0.9):
            print(bpu_types[i], x[l], data1[i][l] / num_repeats)
            break
print('====================')
print('== BTB Timing Collision ==')
for i in range(7):
    for l in range(8):
        if (data2[i][l] >= num_repeats * 0.9):
            print(bpu_types[i], x[l], data2[i][l] / num_repeats)
            break
print('====================')
print('== BTB Speculative Collision ==')
for i in range(7):
    for l in range(8):
        if (data3[i][l] >= num_repeats * 0.9):
            print(bpu_types[i], x[l], data3[i][l] / num_repeats)
            break
print('====================')

# plot
plt.figure(figsize=(6 , 3))
attack = ['PHT Collision', 'BTB Timing', 'BTB Speculative']
for i in range(7):
    plt.plot(x, data1[i] / num_repeats, label=bpu_types[i], marker='o', color='C' + str(i), linestyle='-', linewidth=0.8, markersize=4)
for i in range(7):
    plt.plot(x, data2[i] / num_repeats, label=bpu_types[i], marker='D', color='C' + str(i), linestyle='--', linewidth=0.8, markersize=4)
for i in range(7):
    plt.plot(x, data3[i] / num_repeats, label=bpu_types[i],marker='s', color='C' + str(i), linestyle=':', linewidth=0.8, markersize=4)

# 7 legend for each bpu type
bpu_legend = plt.legend((bpu_types), fontsize=10, ncol=3, loc='upper left')

# 3 legend for each attack type
attack1 = plt.plot(-1, -1, label='PHT Collision', marker='o', color='black', linestyle='-', linewidth=0.8, markersize=4)
attack2 = plt.plot(-1, -1, label='BTB Timing', marker='D', color='black', linestyle='--', linewidth=0.8, markersize=4)
attack3 = plt.plot(-1, -1, label='BTB Speculative', marker='s', color='black', linestyle=':', linewidth=0.8, markersize=4)
attack_legend = plt.legend((attack1[0], attack2[0], attack3[0]), attack, fontsize=10, ncol=1, loc='upper right')

# add legend back
plt.gca().add_artist(bpu_legend)
plt.gca().add_artist(attack_legend)

# plot a line at 90%
plt.axhline(y=0.9, color='black', linestyle='--', linewidth=0.8, alpha=0.5)

plt.xscale('log')
# plt.ticklabel_format(style='plain', axis='x', useMathText=True)
plt.xlabel(r'Branch Accesses ($\mathbf{N}$)')
plt.ylabel(r'Collision Probability ($\mathbf{Pr}$)')
plt.yticks(np.arange(0.0, 1.2, 0.5))
plt.ylim(0, 1.6)
plt.tight_layout()
plt.savefig('fig7.pdf')