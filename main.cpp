// Copyright 2025 iamywang

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// =============================================================================
// BranchGauge: Modeling and Quantifying Leakage in Randomization-Based Secure
// Branch Predictors
//
// author: iamywang
// date: 2024/12/31
// =============================================================================
#include "exps/exp1_reuse.cpp"
#include "exps/exp2_prune.cpp"
#include "exps/exp3_occupancy.cpp"
#include "exps/exp4_leakage.cpp"

uint64_t NUMBER_MAX_BRANCHES = 1e8;

int main(int argc, char **argv) {
  // switch to different attack
  if (argc == 4) {
    int max_branches = std::stoi(argv[2]);
    int max_repeats = std::stoi(argv[3]);
    // init experiments
    Exp1 *exp1 = new Exp1(2, 1024, 4, 1024);
    Exp2 *exp2 = new Exp2(2, 1024, 4, 1024);
    Exp3 *exp3 = new Exp3(2, 1024, 4, 1024);
    Exp4 *exp4 = new Exp4(2, 1024, 4, 1024, max_branches);
    // switch to different attack
    if (std::string(argv[1]) == "reuse-access") {
      exp1->ReuseBranchAccess(max_repeats, 2);
    } else if (std::string(argv[1]) == "reuse-collision") {
      exp1->ReuseCollisionRate(max_repeats, 2);
    } else if (std::string(argv[1]) == "prune-btb-prune") {
      exp2->BTBPruningAccessIterate(max_branches, max_repeats);
    } else if (std::string(argv[1]) == "prune-btb-collision") {
      exp2->BTBCollisionRate(3800, 300000, max_repeats);
    } else if (std::string(argv[1]) == "occupancy-pht-prune") {
      exp3->PHTPruningAccessIterate(max_branches, 1024, max_repeats, 2);
    } else if (std::string(argv[1]) == "occupancy-pht-collision") {
      exp3->PHTCollisionRate(20, 500000, max_repeats, 2);
    } else if (std::string(argv[1]) == "occupancy-btb-prune") {
      exp3->BTBPruningAccessIterate(max_branches, 4096, max_repeats);
    } else if (std::string(argv[1]) == "occupancy-btb-collision") {
      exp3->BTBCollisionRate(600, 200000, max_repeats);
    } else if (std::string(argv[1]) == "leakage-pht") {
      exp4->PHTLeakage(20, 500000, max_repeats, 2);
    } else if (std::string(argv[1]) == "leakage-btb") {
      exp4->BTBLeakage(600, 200000, max_repeats);
    } else {
      std::cout
          << "Usage: ./branch-gauge [attack] [max_branches|max_pruning_sizes] "
             "[max_repeats]"
          << std::endl;
    }
  } else {
    std::cout
        << "Usage: ./branch-gauge [attack] [max_branches|max_pruning_sizes] "
           "[max_repeats]"
        << std::endl;
  }
}