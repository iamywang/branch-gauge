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

class Exp4 {
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
  Exp4(uint64_t counter_bits, uint64_t counter_nums, uint64_t buffer_ways,
       uint64_t buffer_sets, uint64_t secret_size, uint64_t addr_space = 32) {
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
    for (int i = 0; i < secret_size; i++) {
      secrets.push_back(rand() & 0xFFFFFFFF);
    }
  }

  // experiment: PHT leakage under different branch access
  std::vector<std::vector<uint64_t>> PHTLeakage(uint64_t prune_size,
                                                uint64_t max_branch_accesses,
                                                uint64_t max_repeats,
                                                uint64_t counter_bits) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp4: PHTLeakageAccess ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> leakage_stats;
    uint64_t occupancy_size = 1024;
    for (uint64_t num_accesses = 1000; num_accesses <= max_branch_accesses;
         num_accesses += 1000) {
      NUMBER_MAX_BRANCHES = num_accesses;
#ifdef EVALUATION
      std::cout << "PHTLeakageAccess: " << num_accesses << std::endl;
#endif
      // statistics
      std::vector<uint64_t> leakage_stat(7 * 9, 0);
      // simulate the attack
      for (int i = 0; i < max_repeats; i++) {
        std::pair<std::vector<uint64_t>, uint64_t> res_base =
            base_bpu->PHTOccupancy(1e9, counter_bits, prune_size,
                                   occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_bsup =
            bsup->PHTOccupancy(1e9, 3, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_xorbp =
            xorbp->PHTOccupancy(1e9, counter_bits, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_noisyxorbp =
            noisyxorbp->PHTOccupancy(1e9, counter_bits, prune_size,
                                     occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_lsbp =
            lsbp->PHTOccupancy(1e9, counter_bits, prune_size, occupancy_size,
                               attacker_pid);
        std::pair<std::vector<uint64_t>, uint64_t> res_stbpu =
            stbpu->PHTOccupancy(1e9, counter_bits, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_hybp =
            hybp->PHTOccupancy(1e9, counter_bits, prune_size, occupancy_size);

        std::vector<uint64_t> collision_misses(7, 0);
        // check collision probability: base
        for (auto &addr : res_base.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (base_bpu->checkPHTSetCollision(addr, secrets[secret_idx])) {
              collision_misses[0]++;
              break;
            }
          }
        }
        // check collision probability: bsup
        for (auto &addr : res_bsup.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (bsup->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                           secrets[secret_idx],
                                           SecurityDomain::DOM_VICTIM)) {
              collision_misses[1]++;
              break;
            }
          }
        }
        // check collision probability: xorbp
        for (auto &addr : res_xorbp.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (xorbp->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                            secrets[secret_idx],
                                            SecurityDomain::DOM_VICTIM)) {
              collision_misses[2]++;
              break;
            }
          }
        }
        // check collision probability: noisyxorbp
        for (auto &addr : res_noisyxorbp.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (noisyxorbp->checkPHTSetCollision(
                    addr, SecurityDomain::DOM_ATTACKER, secrets[secret_idx],
                    SecurityDomain::DOM_VICTIM)) {
              collision_misses[3]++;
              break;
            }
          }
        }
        // check collision probability: lsbp
        for (auto &addr : res_lsbp.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (lsbp->checkPHTSetCollision(addr, attacker_pid,
                                           SecurityDomain::DOM_ATTACKER,
                                           secrets[secret_idx], victim_pid,
                                           SecurityDomain::DOM_VICTIM)) {
              collision_misses[4]++;
              break;
            }
          }
        }
        // check collision probability: stbpu
        for (auto &addr : res_stbpu.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (stbpu->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                            secrets[secret_idx],
                                            SecurityDomain::DOM_VICTIM)) {
              collision_misses[5]++;
              break;
            }
          }
        }
        // check collision probability: hybp
        for (auto &addr : res_hybp.first) {
          for (uint64_t secret_idx = 0; secret_idx < secrets.size();
               secret_idx++) {
            if (hybp->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                           secrets[secret_idx],
                                           SecurityDomain::DOM_VICTIM)) {
              collision_misses[6]++;
              break;
            }
          }
        }
        for (int j = 0; j < 7; j++) {
          leakage_stat[j * 9 + collision_misses[j]]++;
        }
      }
      leakage_stats.push_back(leakage_stat);
      for (int j = 0; j < leakage_stat.size(); j++) {
        std::cerr << leakage_stat[j] << " ";
      }
      std::cerr << std::endl;
    }
    return leakage_stats;
  }

  // experiment: BTB leakage under different branch access
  std::vector<std::vector<uint64_t>> BTBLeakage(uint64_t prune_size,
                                                uint64_t max_branch_accesses,
                                                uint64_t max_repeats) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp4: BTBLeakageAccess ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> leakage_stats;
    uint64_t occupancy_size = 4096;
    for (uint64_t num_accesses = 1000; num_accesses <= max_branch_accesses;
         num_accesses += 1000) {
      NUMBER_MAX_BRANCHES = num_accesses;
#ifdef EVALUATION
      std::cout << "BTBLeakageAccess: " << num_accesses << std::endl;
#endif
      // statistics
      std::vector<uint64_t> leakage_stat(7 * 9, 0);
      // simulate the attack
      for (int i = 0; i < max_repeats; i++) {
        std::pair<std::vector<uint64_t>, uint64_t> res_base =
            base_bpu->BTBOccupancy(1e9, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_bsup =
            bsup->BTBOccupancy(1e9, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_xorbp =
            xorbp->BTBOccupancy(1e9, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_noisyxorbp =
            noisyxorbp->BTBOccupancy(1e9, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_lsbp =
            lsbp->BTBOccupancy(1e9, prune_size, occupancy_size, attacker_pid);
        std::pair<std::vector<uint64_t>, uint64_t> res_stbpu =
            stbpu->BTBOccupancy(1e9, prune_size, occupancy_size);
        std::pair<std::vector<uint64_t>, uint64_t> res_hybp =
            hybp->BTBOccupancy(1e9, prune_size, occupancy_size);

        std::vector<uint64_t> collision_misses(7, 0);
        // check collision probability: base
        for (auto &addr : res_base.first) {
          base_bpu->lookupBTB(addr, addr);
        }
        for (auto &secret : secrets) {
          base_bpu->lookupBTB(secret, secret);
        }
        for (auto &addr : res_base.first) {
          if (base_bpu->lookupBTB(addr, addr) == -1) {
            collision_misses[0]++;
          }
        }
        // check collision probability: bsup
        for (auto &addr : res_bsup.first) {
          bsup->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        for (auto &secret : secrets) {
          bsup->lookupBTB(secret, secret, SecurityDomain::DOM_VICTIM);
        }
        for (auto &addr : res_bsup.first) {
          if (bsup->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) == -1) {
            collision_misses[1]++;
          }
        }
        // check collision probability: xorbp
        for (auto &addr : res_xorbp.first) {
          xorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        for (auto &secret : secrets) {
          xorbp->lookupBTB(secret, secret, SecurityDomain::DOM_VICTIM);
        }
        for (auto &addr : res_xorbp.first) {
          if (xorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
              -1) {
            collision_misses[2]++;
          }
        }
        // check collision probability: noisyxorbp
        for (auto &addr : res_noisyxorbp.first) {
          noisyxorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        for (auto &secret : secrets) {
          noisyxorbp->lookupBTB(secret, secret, SecurityDomain::DOM_VICTIM);
        }
        for (auto &addr : res_noisyxorbp.first) {
          if (noisyxorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
              -1) {
            collision_misses[3]++;
          }
        }
        // check collision probability: lsbp
        for (auto &addr : res_lsbp.first) {
          lsbp->lookupBTB(addr, addr, attacker_pid,
                          SecurityDomain::DOM_ATTACKER);
        }
        for (auto &secret : secrets) {
          lsbp->lookupBTB(secret, secret, victim_pid,
                          SecurityDomain::DOM_VICTIM);
        }
        for (auto &addr : res_lsbp.first) {
          if (lsbp->lookupBTB(addr, addr, attacker_pid,
                              SecurityDomain::DOM_ATTACKER) == -1) {
            collision_misses[4]++;
          }
        }
        // check collision probability: stbpu
        for (auto &addr : res_stbpu.first) {
          stbpu->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        for (auto &secret : secrets) {
          stbpu->lookupBTB(secret, secret, SecurityDomain::DOM_VICTIM);
        }
        for (auto &addr : res_stbpu.first) {
          if (stbpu->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
              -1) {
            collision_misses[5]++;
          }
        }
        // check collision probability: hybp
        for (auto &addr : res_hybp.first) {
          hybp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        for (auto &secret : secrets) {
          hybp->lookupBTB(secret, secret, SecurityDomain::DOM_VICTIM);
        }
        for (auto &addr : res_hybp.first) {
          if (hybp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) == -1) {
            collision_misses[6]++;
          }
        }
        for (int j = 0; j < 7; j++) {
          uint64_t idx = collision_misses[j] / 4;
          if (idx >= secrets.size()) {
            idx = secrets.size();
          }
          leakage_stat[j * 9 + idx]++;
        }
      }
      leakage_stats.push_back(leakage_stat);
      for (int j = 0; j < leakage_stat.size(); j++) {
        std::cerr << leakage_stat[j] << " ";
      }
      std::cerr << std::endl;
    }
    return leakage_stats;
  }
};