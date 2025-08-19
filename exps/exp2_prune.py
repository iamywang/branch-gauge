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
# date: 2024/12/27
# =============================================================================
import os
import threading

global_num_repeats = 1000

def exp2_pruning_access():
    # set the file path
    bin_file = "../build/branch-gauge"
    output_dir = "./res"
    output_file = os.path.join(output_dir, "exp2_pruning_access.txt")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # set the binary parameters
    num_repeats = global_num_repeats
    num_pruning_sizes = 4000
    # execute the binary
    cmd = "{} prune-btb-prune {} {} 2> {}".format(bin_file, num_pruning_sizes, num_repeats, output_file)
    os.system(cmd)

def exp2_pruning_collision():
    # set the file path
    bin_file = "../build/branch-gauge"
    output_dir = "./res"
    output_file = os.path.join(output_dir, "exp2_pruning_collision.txt")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # set the binary parameters
    num_repeats = global_num_repeats
    num_pruning_sizes = 3800
    # execute the binary
    cmd = "{} prune-btb-collision {} {} 2> {}".format(bin_file, num_pruning_sizes, num_repeats, output_file)
    os.system(cmd)

# execute the experiment (multi-threading)
if __name__ == "__main__":
    threads = []
    threads.append(threading.Thread(target=exp2_pruning_access))
    threads.append(threading.Thread(target=exp2_pruning_collision))
    print("Experiment 2 started.")
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    print("Experiment 2 finished.")