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
# date: 2025/01/09
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
f = open('../res/exp3_btb_collision_rate.txt', 'r')
lines = f.readlines()
f.close()

num_repeats = 1000

# parse data to 7 * 200 matrix (1000 to 200000)
data = np.zeros((7, 200))
for l in range(len(lines)):
    line = lines[l].split(' ')
    for i in range(7):
        data[i][l] = int(line[i])

# print the index for the first value that larger than 90%
bpu_types = ['Baseline', 'BSUP', 'XOR', 'Noisy-XOR', 'LS-BP', 'STBPU', 'HyBP']
print('== BTB Occupancy Collision ==')
for i in range(7):
    for j in range(200):
        if data[i][j] > num_repeats * 0.9:
            print(bpu_types[i], (j + 1) * 1000, data[i][j] / num_repeats)
            break
print('====================')

# plot
plt.figure(figsize=(6 , 3))
x = [20000, 40000, 60000, 80000, 100000, 120000, 140000, 160000, 180000, 200000]
bar_width = 0.13
bar_x = np.arange(len(x))
for i in range(len(x)):
    x_index = int(x[i] / 1000) - 1
    plt.bar(bar_x[i] - 2.5 * bar_width - 0.05, data[1][x_index] / num_repeats, bar_width, color='C1')
    plt.bar(bar_x[i] - 1.5 * bar_width - 0.03, data[2][x_index] / num_repeats, bar_width, color='C2')
    plt.bar(bar_x[i] - 0.5 * bar_width - 0.01, data[3][x_index] / num_repeats, bar_width, color='C3')
    plt.bar(bar_x[i] + 0.5 * bar_width + 0.01, data[4][x_index] / num_repeats, bar_width, color='C4')
    plt.bar(bar_x[i] + 1.5 * bar_width + 0.03, data[5][x_index] / num_repeats, bar_width, color='C5')
    plt.bar(bar_x[i] + 2.5 * bar_width + 0.05, data[6][x_index] / num_repeats, bar_width, color='C6')
plt.xticks(np.arange(len(x)), ['$' + str(i) + '$' for i in x], rotation=30)
plt.legend(bpu_types[1:], fontsize=10, ncol=3)
# plot a line at 90%
plt.axhline(y=0.9, color='black', linestyle='--', linewidth=0.8, alpha=0.5)
plt.ticklabel_format(style='sci', axis='y', scilimits=(0, 2), useMathText=True)
plt.xlabel(r'Branch Accesses ($\mathbf{N}$)')
plt.ylabel(r'Collision Probability ($\mathbf{Pr}$)')
plt.yticks(np.arange(0.0, 1.2, 0.5))
plt.ylim(0, 1.4)
plt.tight_layout()
plt.savefig('fig13.pdf')