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
# date: 2025/01/01
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
f1 = open('../res/exp4_pht_access_1.txt', 'r')
f2 = open('../res/exp4_pht_access_2.txt', 'r')
f3 = open('../res/exp4_pht_access_3.txt', 'r')
f4 = open('../res/exp4_pht_access_4.txt', 'r')
lines1 = f1.readlines()
lines2 = f2.readlines()
lines3 = f3.readlines()
lines4 = f4.readlines()
f1.close()
f2.close()
f3.close()
f4.close()

num_repeats = 1000
num_split = 5

# parse data to 63 * 500 matrix
data1 = np.zeros((63, 500))
data2 = np.zeros((63, 500))
data3 = np.zeros((63, 500))
data4 = np.zeros((63, 500))
for l in range(len(lines1)):
    line = lines1[l].split(' ')
    for i in range(63):
        data1[i][l] = int(line[i])
for l in range(len(lines2)):
    line = lines2[l].split(' ')
    for i in range(63):
        data2[i][l] = int(line[i])
for l in range(len(lines3)):
    line = lines3[l].split(' ')
    for i in range(63):
        data3[i][l] = int(line[i])
for l in range(len(lines4)):
    line = lines4[l].split(' ')
    for i in range(63):
        data4[i][l] = int(line[i])

# calculate the maximal leakage
bpu_types = ['Baseline', 'BSUP', 'XOR', 'Noisy-XOR', 'LS-BP', 'STBPU', 'HyBP']
leakage_1 = np.zeros((7, 500))
leakage_2 = np.zeros((7, 500))
leakage_4 = np.zeros((7, 500))
for i in range(7):
    for j in range(500):
        # dump collision data
        collisions = np.zeros(5)
        for k in range(5):
            collisions[k] = np.max([data1[i * 9 + k][j], data2[i * 9 + k][j], data3[i * 9 + k][j], data4[i * 9 + k][j]])
        # calculate collision probability
        prob = np.zeros(5)
        prob[0] = collisions[0] / num_repeats
        prob[1] = collisions[1] / num_repeats / 4
        prob[2] = collisions[2] / num_repeats / 6
        prob[3] = collisions[3] / num_repeats / 4
        prob[4] = collisions[4] / num_repeats
        # calculate the maximal leakage
        leakage_1[i][j] = np.log2(np.sum(prob))
        # calculate collision probability
        prob[0] = collisions[0] / num_repeats
        prob[1] = collisions[1] / num_repeats / 2
        prob[2] = collisions[2] / num_repeats / 3
        prob[3] = collisions[3] / num_repeats / 2
        prob[4] = collisions[4] / num_repeats
        # calculate the maximal leakage
        leakage_2[i][j] = np.log2(np.sum(prob))
        # calculate collision probability
        prob[0] = collisions[0] / num_repeats
        prob[1] = collisions[1] / num_repeats
        prob[2] = collisions[2] / num_repeats / 6 * 4
        prob[3] = collisions[3] / num_repeats
        prob[4] = collisions[4] / num_repeats
        # calculate the maximal leakage
        leakage_4[i][j] = np.log2(np.sum(prob))
        if leakage_1[i][j] < 0:
            leakage_1[i][j] = 0
        if leakage_2[i][j] < 0:
            leakage_2[i][j] = 0
        if leakage_4[i][j] < 0:
            leakage_4[i][j] = 0

# print the maximal leakage
print('== PHT Maximal Leakage ==')
for i in range(7):
    print("{} & %.2f & %.2f & %.2f & %.2f & %.2f & %.2f & %.2f & %.2f & %.2f \\\\".format(bpu_types[i]) % (np.max(leakage_1[i][0:10]), np.max(leakage_1[i][0:100]), np.max(leakage_1[i]), np.max(leakage_2[i][0:10]), np.max(leakage_2[i][0:100]), np.max(leakage_2[i]), np.max(leakage_4[i][0:10]), np.max(leakage_4[i][0:100]), np.max(leakage_4[i])))
print('====================')
