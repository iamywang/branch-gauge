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
# date: 2024/12/30
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
f = open('../res/exp1_reuse_access.txt', 'r')
lines = f.readlines()
f.close()

num_repeats = 1000

# parse data to from 21 * 1000 to 7 * 1000 matrix
data1 = np.zeros((7, num_repeats)) # pht
data2 = np.zeros((7, num_repeats)) # btb timing
data3 = np.zeros((7, num_repeats)) # btb speculative
for l in range(len(lines)):
    line = lines[l].split(' ') # 21 values
    for i in range(7):
        data1[i][l] = int(line[i])
        data2[i][l] = int(line[i + 7])
        data3[i][l] = int(line[i + 14])

# calculate the average (from 7 * 1000 to 7 * 1)
avg1 = np.mean(data1, axis=1)
avg2 = np.mean(data2, axis=1)
avg3 = np.mean(data3, axis=1)

# plot
plt.figure(figsize=(6 , 3))
x = ['Baseline', 'BSUP', 'XOR', 'Noisy-XOR', 'LS-BP', 'STBPU', 'HyBP']
attack = ['PHT Collision', 'BTB Timing', 'BTB Speculative']
bar_width = 0.25
bar_x = np.arange(len(x))
for i in range(len(x)):
    bar1 = plt.bar(bar_x[i] - bar_width - 0.03, avg1[i], width=bar_width, color='C0')
    bar2 = plt.bar(bar_x[i], avg2[i], width=bar_width, color='C1')
    bar3 = plt.bar(bar_x[i] + bar_width + 0.03, avg3[i], width=bar_width, color='C2')
    if int(avg1[i]) < 1e7:
        plt.text(bar_x[i] - bar_width - 0.03, avg1[i], '$' + str(int(avg1[i])) + '$', ha='center', va='bottom', fontsize=9, rotation=90)
    else:
        plt.text(bar_x[i] - bar_width - 0.03, avg1[i], '$>10^8$', ha='center', va='bottom', fontsize=9, rotation=90)
    if int(avg2[i]) < 1e7:
        plt.text(bar_x[i], avg2[i], '$' + str(int(avg2[i])) + '$', ha='center', va='bottom', fontsize=9, rotation=90)
    else:
        plt.text(bar_x[i], avg2[i], '$>10^8$', ha='center', va='bottom', fontsize=9, rotation=90)
    if int(avg3[i]) < 1e7:
        plt.text(bar_x[i] + bar_width + 0.03, avg3[i], '$' + str(int(avg3[i])) + '$', ha='center', va='bottom', fontsize=9, rotation=90)
    else:
        plt.text(bar_x[i] + bar_width + 0.03, avg3[i], '$>10^8$', ha='center', va='bottom', fontsize=9, rotation=90)
plt.legend((bar1, bar2, bar3), attack, fontsize=10, ncol=3)
plt.xticks(bar_x, x)
plt.ticklabel_format(style='sci', axis='y', scilimits=(0, 2), useMathText=True)
plt.xlabel('Branch Predictor')
plt.ylabel(r'Branch Accesses ($\mathbf{N}$)')
plt.yscale('log')
plt.ylim(0, 2e11)
plt.tight_layout()
plt.savefig('fig6.pdf')