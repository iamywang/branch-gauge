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
# date: 2025/04/21
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
f = open('../res/exp2_pruning_access.txt', 'r')
lines = f.readlines()
f.close()

# parse data to 7 * 40 matrix
data = np.zeros((7, 40))
for l in range(len(lines)):
    line = lines[l].split(' ')
    for i in range(7):
        data[i][l] = int(line[i])

# print the index for the minimum value
bpu_types = ['Baseline', 'BSUP', 'XOR', 'Noisy-XOR', 'LS-BP', 'STBPU', 'HyBP']
print('== Pruning Access ==')
for i in range(7):
    print(bpu_types[i], (np.argmin(data[i]) + 1) * 100, np.min(data[i]))
print('====================')

# plot
plt.figure(figsize=(6 , 3))
x = np.arange(100, 4100, 100)
plt.plot(x, data[0], label=bpu_types[0], linewidth=0.8, marker='o', markersize=4, markevery=3)
plt.plot(x, data[1], label=bpu_types[1], linewidth=0.8, marker='D', markersize=4, markevery=4)
plt.plot(x, data[2], label=bpu_types[2], linewidth=0.8, marker='s', markersize=4, markevery=5)
plt.plot(x, data[3], label=bpu_types[3], linewidth=0.8, marker='^', markersize=4, markevery=7)
plt.plot(x, data[4], label=bpu_types[4], linewidth=0.8, marker='*', markersize=4, markevery=10)
plt.plot(x, data[5], label=bpu_types[5], linewidth=0.8, marker='x', markersize=4, markevery=11)
plt.plot(x, data[6], label=bpu_types[6], linewidth=0.8, marker='p', markersize=4, markevery=13)
plt.legend(fontsize=10, ncol=4)
plt.ticklabel_format(style='sci', axis='y', scilimits=(0, 2), useMathText=True)
plt.xlabel(r'Pruning Set Size ($\mathbb{K}$)')
plt.ylabel(r'Branch Accesses ($\mathbf{N}$)')
plt.yscale('log')
plt.tight_layout()
plt.savefig('fig8.pdf')