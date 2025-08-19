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
# date: 2025/01/10
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
data = np.zeros((7, 8))
for l in range(len(lines)):
    line = lines[l].split(' ') # 21 values
    for i in range(7):
        data[i][l] = int(line[i + 7])

# print the index of the first 90% value
bpu_types = ['Baseline', 'BSUP', 'XOR', 'Noisy-XOR', 'LS-BP', 'STBPU', 'HyBP']
num_accesses = [10000, 50000, 100000, 200000, 500000, 1000000, 10000000, 100000000]

# leakage
print('== BTB Single-Bit Leakage ==')
leakage = np.zeros((7, 8))
for i in range(7):
    for l in range(8):
        leakage[i][l] = np.log2(1 + data[i][l] / num_repeats)
        if leakage[i][l] < 0:
            leakage[i][l] = 0
for i in range(7):
    print("{} & %.2f & %.2f & %.2f \\\\".format(bpu_types[i]) % (leakage[i][0], leakage[i][2], leakage[i][5]))
print('==============================')

# plot
plt.figure(figsize=(6 , 3))
bar_width = 0.2
bar_x = np.arange(len(bpu_types))
for i in range(len(bpu_types)):
    bar1 = plt.bar(bar_x[i] - 1.5 * bar_width - 0.03, leakage[i][0], width=bar_width, color='C0')
    bar2 = plt.bar(bar_x[i] - 0.5 * bar_width - 0.01, leakage[i][2], width=bar_width, color='C1')
    bar3 = plt.bar(bar_x[i] + 0.5 * bar_width + 0.01, leakage[i][5], width=bar_width, color='C2')
    bar4 = plt.bar(bar_x[i] + 1.5 * bar_width + 0.03, leakage[i][6], width=bar_width, color='C3')
    plt.text(bar_x[i] - 1.5 * bar_width - 0.03, leakage[i][0], '$%.2f$' % leakage[i][0], ha='center', va='bottom', fontsize=9, rotation=90)
    plt.text(bar_x[i] - 0.5 * bar_width - 0.01, leakage[i][2], '$%.2f$' % leakage[i][2], ha='center', va='bottom', fontsize=9, rotation=90)
    plt.text(bar_x[i] + 0.5 * bar_width + 0.01, leakage[i][5], '$%.2f$' % leakage[i][5], ha='center', va='bottom', fontsize=9, rotation=90)
    plt.text(bar_x[i] + 1.5 * bar_width + 0.03, leakage[i][6], '$%.2f$' % leakage[i][6], ha='center', va='bottom', fontsize=9, rotation=90)
legends = [r'$10^4$', r'$10^5$', r'$10^6$', r'$10^7$']
plt.legend((bar1, bar2, bar3, bar4), legends, fontsize=10, ncol=4)
plt.xticks(bar_x, bpu_types)
plt.xlabel('Branch Predictor')
plt.ylabel(r'Maximal Leakage ($\mathbf{L_{max}}$)')
plt.yticks(np.arange(0.0, 1.2, 0.5))
plt.ylim(0, 1.4)
plt.tight_layout()
plt.savefig('fig14.pdf')