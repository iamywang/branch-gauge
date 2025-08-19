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
// date: 2024/12/27
// =============================================================================
#include <cstdint>
#include <iostream>
#include <vector>

#include "include/predictors/BSUP.hpp"
#include "include/predictors/BaseBPU.hpp"
#include "include/predictors/HyBP.hpp"
#include "include/predictors/LSBP.hpp"
#include "include/predictors/NoisyXorBP.hpp"
#include "include/predictors/STBPU.hpp"
#include "include/predictors/XorBP.hpp"
#include "include/utils/Utils.hpp"

class Exp2 {
 private:
  std::vector<uint64_t> secrets;
  BaseBPU *base_bpu;
  BSUP *bsup;
  XorBP *xorbp;
  NoisyXorBP *noisyxorbp;
  LSBP *lsbp;
  STBPU *stbpu;
  HyBP *hybp;

  uint64_t attacker_pid;
  uint64_t victim_pid;

 public:
  Exp2(uint64_t counter_bits, uint64_t counter_nums, uint64_t buffer_ways,
       uint64_t buffer_sets, uint64_t addr_space = 32) {
    srand(time(NULL));
    // init branch predictors
    base_bpu = new BaseBPU(addr_space);
    base_bpu->initPHT(counter_bits, counter_nums);
    base_bpu->initBTB(buffer_ways, buffer_sets);

    bsup = new BSUP(addr_space);
    bsup->initPHT(3, counter_nums);
    bsup->initBTB(buffer_ways, buffer_sets);

    xorbp = new XorBP(addr_space);
    xorbp->initPHT(counter_bits, counter_nums);
    xorbp->initBTB(buffer_ways, buffer_sets);

    noisyxorbp = new NoisyXorBP(addr_space);
    noisyxorbp->initPHT(counter_bits, counter_nums);
    noisyxorbp->initBTB(buffer_ways, buffer_sets);

    lsbp = new LSBP(addr_space);
    lsbp->initPHT(counter_bits, counter_nums);
    lsbp->initBTB(buffer_ways, buffer_sets);
#ifdef RANDOM_PID
    attacker_pid = rand() & 0xFFFFFFFF;
    victim_pid = rand() & 0xFFFFFFFF;
#else
    attacker_pid = ProcessorPID::PID_ATTACKER;
    victim_pid = ProcessorPID::PID_VICTIM;
#endif

    stbpu = new STBPU(addr_space);
    stbpu->initPHT(counter_bits, counter_nums);
    stbpu->initBTB(buffer_ways, buffer_sets);

    hybp = new HyBP(addr_space);
    hybp->initPHT(counter_bits, counter_nums);
    hybp->initBTB(buffer_ways, buffer_sets);

    // init secrets
    for (int i = 0; i < 16; i++) {
      secrets.push_back(rand() & 0xFFFFFFFF);
    }
  }

  // experiment: BTB access under different pruning set size
  std::vector<uint64_t> BTBPruningAccess(uint64_t prune_size,
                                         uint64_t repeats) {
    srand(time(NULL));
    // statistics
    std::vector<uint64_t> access_stat(7, 0);
    uint64_t num_loops = 1e9;
    // simulate the attack
    for (int i = 0; i < repeats; i++) {
      uint64_t victim_addr = secrets[0];
      uint64_t target_addr = secrets[1];
      std::pair<std::vector<uint64_t>, uint64_t> res_base =
          base_bpu->BTBPrune(num_loops, victim_addr, prune_size, 1);
      std::pair<std::vector<uint64_t>, uint64_t> res_bsup =
          bsup->BTBPrune(num_loops, victim_addr, prune_size, 1);
      std::pair<std::vector<uint64_t>, uint64_t> res_xorbp =
          xorbp->BTBPrune(num_loops, victim_addr, prune_size, 1);
      std::pair<std::vector<uint64_t>, uint64_t> res_noisyxorbp =
          noisyxorbp->BTBPrune(num_loops, victim_addr, prune_size, 1);
      std::pair<std::vector<uint64_t>, uint64_t> res_lsbp = lsbp->BTBPrune(
          num_loops, victim_addr, prune_size, 1, attacker_pid, victim_pid);
      std::pair<std::vector<uint64_t>, uint64_t> res_stbpu =
          stbpu->BTBPrune(num_loops, victim_addr, prune_size, 1);
      std::pair<std::vector<uint64_t>, uint64_t> res_hybp =
          hybp->BTBPrune(num_loops, victim_addr, prune_size, 1);
      // save the statistics
      access_stat[0] += res_base.second;
      access_stat[1] += res_bsup.second;
      access_stat[2] += res_xorbp.second;
      access_stat[3] += res_noisyxorbp.second;
      access_stat[4] += res_lsbp.second;
      access_stat[5] += res_stbpu.second;
      access_stat[6] += res_hybp.second;
    }
    for (int j = 0; j < access_stat.size(); j++) {
      std::cerr << access_stat[j] / repeats << " ";
    }
    std::cerr << std::endl;
    return access_stat;
  }

  std::vector<std::vector<uint64_t>> BTBPruningAccessIterate(
      uint64_t max_pruning_sizes, uint64_t max_repeats) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp2: BTBPruningAccessIterate ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> access_stats;
    for (uint64_t prune_size = 100; prune_size <= max_pruning_sizes;
         prune_size += 100) {
#ifdef EVALUATION
      std::cout << "BTBPruningAccessIterate: " << prune_size << std::endl;
#endif
      std::vector<uint64_t> access_stat =
          BTBPruningAccess(prune_size, max_repeats);
      access_stats.push_back(access_stat);
    }
    return access_stats;
  }

  // experiment: BTB collison under different eviction set size
  std::vector<std::vector<uint64_t>> BTBCollisionRate(
      uint64_t prune_size, uint64_t max_branch_accesses, uint64_t max_repeats) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp2: BTBCollisionRate ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> collision_stats;
    for (uint64_t num_accesses = 1000; num_accesses <= max_branch_accesses;
         num_accesses += 1000) {
      NUMBER_MAX_BRANCHES = num_accesses;
#ifdef EVALUATION
      std::cout << "BTBPruneCollisionRate: " << num_accesses << std::endl;
#endif
      uint64_t victim_addr = secrets[0];
      // statistics
      std::vector<uint64_t> collision_stat(7, 0);
      // simulate the attack
      for (int i = 0; i < max_repeats; i++) {
        std::pair<std::vector<uint64_t>, uint64_t> res_base =
            base_bpu->BTBPrune(1e9, victim_addr, 100, 4);
        std::pair<std::vector<uint64_t>, uint64_t> res_bsup =
            bsup->BTBPrune(1e9, victim_addr, prune_size, 4);
        std::pair<std::vector<uint64_t>, uint64_t> res_xorbp =
            xorbp->BTBPrune(1e9, victim_addr, 100, 4);
        std::pair<std::vector<uint64_t>, uint64_t> res_noisyxorbp =
            noisyxorbp->BTBPrune(1e9, victim_addr, prune_size, 4);
        std::pair<std::vector<uint64_t>, uint64_t> res_lsbp = lsbp->BTBPrune(
            1e9, victim_addr, prune_size, 4, attacker_pid, victim_pid);
        std::pair<std::vector<uint64_t>, uint64_t> res_stbpu =
            stbpu->BTBPrune(1e9, victim_addr, prune_size, 4);
        std::pair<std::vector<uint64_t>, uint64_t> res_hybp =
            hybp->BTBPrune(1e9, victim_addr, prune_size, 4);
        // check collision probability: base
        if (res_base.second <= num_accesses) {
          for (auto &addr : res_base.first) {
            base_bpu->lookupBTB(addr, addr);
          }
          base_bpu->lookupBTB(victim_addr, victim_addr);
          for (auto &addr : res_base.first) {
            if (base_bpu->lookupBTB(addr, addr) == -1) {
              collision_stat[0]++;
              break;
            }
          }
        }
        // check collision probability: bsup
        if (res_bsup.second <= num_accesses) {
          for (auto &addr : res_bsup.first) {
            bsup->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
          }
          bsup->lookupBTB(victim_addr, victim_addr, SecurityDomain::DOM_VICTIM);
          for (auto &addr : res_bsup.first) {
            if (bsup->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
                -1) {
              collision_stat[1]++;
              break;
            }
          }
        }
        // check collision probability: xorbp
        if (res_xorbp.second <= num_accesses) {
          for (auto &addr : res_xorbp.first) {
            xorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
          }
          xorbp->lookupBTB(victim_addr, victim_addr,
                           SecurityDomain::DOM_VICTIM);
          for (auto &addr : res_xorbp.first) {
            if (xorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
                -1) {
              collision_stat[2]++;
              break;
            }
          }
        }
        // check collision probability: noisyxorbp
        if (res_noisyxorbp.second <= num_accesses) {
          for (auto &addr : res_noisyxorbp.first) {
            noisyxorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
          }
          noisyxorbp->lookupBTB(victim_addr, victim_addr,
                                SecurityDomain::DOM_VICTIM);
          for (auto &addr : res_noisyxorbp.first) {
            if (noisyxorbp->lookupBTB(addr, addr,
                                      SecurityDomain::DOM_ATTACKER) == -1) {
              collision_stat[3]++;
              break;
            }
          }
        }
        // check collision probability: lsbp
        if (res_lsbp.second <= num_accesses) {
          for (auto &addr : res_lsbp.first) {
            lsbp->lookupBTB(addr, addr, attacker_pid,
                            SecurityDomain::DOM_ATTACKER);
          }
          lsbp->lookupBTB(victim_addr, victim_addr, victim_pid,
                          SecurityDomain::DOM_VICTIM);
          for (auto &addr : res_lsbp.first) {
            if (lsbp->lookupBTB(addr, addr, attacker_pid,
                                SecurityDomain::DOM_ATTACKER) == -1) {
              collision_stat[4]++;
              break;
            }
          }
        }
        // check collision probability: stbpu
        if (res_stbpu.second <= num_accesses) {
          for (auto &addr : res_stbpu.first) {
            stbpu->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
          }
          stbpu->lookupBTB(victim_addr, victim_addr,
                           SecurityDomain::DOM_VICTIM);
          for (auto &addr : res_stbpu.first) {
            if (stbpu->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
                -1) {
              collision_stat[5]++;
              break;
            }
          }
        }
        // check collision probability: hybp
        if (res_hybp.second <= num_accesses) {
          for (auto &addr : res_hybp.first) {
            hybp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
          }
          hybp->lookupBTB(victim_addr, victim_addr, SecurityDomain::DOM_VICTIM);
          for (auto &addr : res_hybp.first) {
            if (hybp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
                -1) {
              collision_stat[6]++;
              break;
            }
          }
        }
      }
      collision_stats.push_back(collision_stat);
      for (int j = 0; j < collision_stat.size(); j++) {
        std::cerr << collision_stat[j] << " ";
      }
      std::cerr << std::endl;
    }
    return collision_stats;
  }
};