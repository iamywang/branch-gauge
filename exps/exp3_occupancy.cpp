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
// date: 2024/12/30
// =============================================================================
#include <cstdint>
#include <iostream>

#include "include/predictors/BSUP.hpp"
#include "include/predictors/BaseBPU.hpp"
#include "include/predictors/HyBP.hpp"
#include "include/predictors/LSBP.hpp"
#include "include/predictors/NoisyXorBP.hpp"
#include "include/predictors/STBPU.hpp"
#include "include/predictors/XorBP.hpp"
#include "include/utils/Utils.hpp"

class Exp3 {
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
  Exp3(uint64_t counter_bits, uint64_t counter_nums, uint64_t buffer_ways,
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

  // experiment: PHT access under different pruning set size
  std::vector<uint64_t> PHTPruningAccess(uint64_t prune_size,
                                         uint64_t occupancy_size,
                                         uint64_t repeats,
                                         uint64_t counter_bits) {
    srand(time(NULL));
    // statistics
    std::vector<uint64_t> access_stat(7, 0);
    uint64_t num_loops = 1e9;
    // simulate the attack
    for (int i = 0; i < repeats; i++) {
      std::pair<std::vector<uint64_t>, uint64_t> res_base =
          base_bpu->PHTOccupancy(num_loops, counter_bits, prune_size,
                                 occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_bsup =
          bsup->PHTOccupancy(num_loops, 3, prune_size, occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_xorbp =
          xorbp->PHTOccupancy(num_loops, counter_bits, prune_size,
                              occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_noisyxorbp =
          noisyxorbp->PHTOccupancy(num_loops, counter_bits, prune_size,
                                   occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_lsbp = lsbp->PHTOccupancy(
          num_loops, counter_bits, prune_size, occupancy_size, attacker_pid);
      std::pair<std::vector<uint64_t>, uint64_t> res_stbpu =
          stbpu->PHTOccupancy(num_loops, counter_bits, prune_size,
                              occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_hybp = hybp->PHTOccupancy(
          num_loops, counter_bits, prune_size, occupancy_size);
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

  std::vector<std::vector<uint64_t>> PHTPruningAccessIterate(
      uint64_t max_pruning_sizes, uint64_t occupancy_size, uint64_t max_repeats,
      uint64_t counter_bits) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp3: PHTPruningAccessIterate ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> access_stats;
    for (uint64_t prune_size = 1; prune_size <= max_pruning_sizes;
         prune_size++) {
#ifdef EVALUATION
      std::cout << "PHTOccupancyPruningAccessIterate: " << prune_size
                << std::endl;
#endif
      std::vector<uint64_t> access_stat = PHTPruningAccess(
          prune_size, occupancy_size, max_repeats, counter_bits);
      access_stats.push_back(access_stat);
    }
    return access_stats;
  }

  // experiment: BTB access under different pruning set size
  std::vector<uint64_t> BTBPruningAccess(uint64_t prune_size,
                                         uint64_t occupancy_size,
                                         uint64_t repeats) {
    srand(time(NULL));
    // statistics
    std::vector<uint64_t> access_stat(7, 0);
    uint64_t num_loops = 1e9;
    // simulate the attack
    for (int i = 0; i < repeats; i++) {
      std::pair<std::vector<uint64_t>, uint64_t> res_base =
          base_bpu->BTBOccupancy(num_loops, prune_size, occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_bsup =
          bsup->BTBOccupancy(num_loops, prune_size, occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_xorbp =
          xorbp->BTBOccupancy(num_loops, prune_size, occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_noisyxorbp =
          noisyxorbp->BTBOccupancy(num_loops, prune_size, occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_lsbp = lsbp->BTBOccupancy(
          num_loops, prune_size, occupancy_size, attacker_pid);
      std::pair<std::vector<uint64_t>, uint64_t> res_stbpu =
          stbpu->BTBOccupancy(num_loops, prune_size, occupancy_size);
      std::pair<std::vector<uint64_t>, uint64_t> res_hybp =
          hybp->BTBOccupancy(num_loops, prune_size, occupancy_size);
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
      uint64_t max_pruning_sizes, uint64_t occupancy_size,
      uint64_t max_repeats) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp3: BTBPruningAccessIterate ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> access_stats;
    for (uint64_t prune_size = 100; prune_size <= max_pruning_sizes;
         prune_size += 100) {
#ifdef EVALUATION
      std::cout << "BTBOccupancyPruningAccessIterate: " << prune_size
                << std::endl;
#endif
      std::vector<uint64_t> access_stat =
          BTBPruningAccess(prune_size, occupancy_size, max_repeats);
      access_stats.push_back(access_stat);
    }
    return access_stats;
  }

  // experiment: PHT collision rate under different occupancy size
  std::vector<std::vector<uint64_t>> PHTCollisionRate(
      uint64_t prune_size, uint64_t max_branch_accesses, uint64_t max_repeats,
      uint64_t counter_bits) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp3: PHTCollisionRate ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> collision_stats;
    uint64_t occupancy_size = 1024;
    for (uint64_t num_accesses = 1000; num_accesses <= max_branch_accesses;
         num_accesses += 1000) {
      NUMBER_MAX_BRANCHES = num_accesses;
#ifdef EVALUATION
      std::cout << "PHTCollisionRate: " << num_accesses << std::endl;
#endif
      uint64_t victim_addr = secrets[0];
      // statistics
      std::vector<uint64_t> collision_stat(7, 0);
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
        // check collision probability
        for (auto &addr : res_base.first) {
          if (base_bpu->checkPHTSetCollision(addr, victim_addr)) {
            collision_stat[0]++;
            break;
          }
        }
        for (auto &addr : res_bsup.first) {
          if (bsup->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                         victim_addr,
                                         SecurityDomain::DOM_VICTIM)) {
            collision_stat[1]++;
            break;
          }
        }
        for (auto &addr : res_xorbp.first) {
          if (xorbp->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                          victim_addr,
                                          SecurityDomain::DOM_VICTIM)) {
            collision_stat[2]++;
            break;
          }
        }
        for (auto &addr : res_noisyxorbp.first) {
          if (noisyxorbp->checkPHTSetCollision(
                  addr, SecurityDomain::DOM_ATTACKER, victim_addr,
                  SecurityDomain::DOM_VICTIM)) {
            collision_stat[3]++;
            break;
          }
        }
        for (auto &addr : res_lsbp.first) {
          if (lsbp->checkPHTSetCollision(
                  addr, attacker_pid, SecurityDomain::DOM_ATTACKER, victim_addr,
                  victim_pid, SecurityDomain::DOM_VICTIM)) {
            collision_stat[4]++;
            break;
          }
        }
        for (auto &addr : res_stbpu.first) {
          if (stbpu->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                          victim_addr,
                                          SecurityDomain::DOM_VICTIM)) {
            collision_stat[5]++;
            break;
          }
        }
        for (auto &addr : res_hybp.first) {
          if (hybp->checkPHTSetCollision(addr, SecurityDomain::DOM_ATTACKER,
                                         victim_addr,
                                         SecurityDomain::DOM_VICTIM)) {
            collision_stat[6]++;
            break;
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

  // experiment: BTB collision rate under different occupancy size
  std::vector<std::vector<uint64_t>> BTBCollisionRate(
      uint64_t prune_size, uint64_t max_branch_accesses, uint64_t max_repeats) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp3: BTBCollisionRate ==" << std::endl;
#endif
    std::vector<std::vector<uint64_t>> collision_stats;
    uint64_t occupancy_size = 4096;
    for (uint64_t num_accesses = 1000; num_accesses <= max_branch_accesses;
         num_accesses += 1000) {
      NUMBER_MAX_BRANCHES = num_accesses;
#ifdef EVALUATION
      std::cout << "BTBCollisionRate: " << num_accesses << std::endl;
#endif
      uint64_t victim_addr = secrets[0];
      // statistics
      std::vector<uint64_t> collision_stat(7, 0);
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
        // check collision probability: base
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
        // check collision probability: bsup
        for (auto &addr : res_bsup.first) {
          bsup->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        bsup->lookupBTB(victim_addr, victim_addr, SecurityDomain::DOM_VICTIM);
        for (auto &addr : res_bsup.first) {
          if (bsup->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) == -1) {
            collision_stat[1]++;
            break;
          }
        }
        // check collision probability: xorbp
        for (auto &addr : res_xorbp.first) {
          xorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        xorbp->lookupBTB(victim_addr, victim_addr, SecurityDomain::DOM_VICTIM);
        for (auto &addr : res_xorbp.first) {
          if (xorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
              -1) {
            collision_stat[2]++;
            break;
          }
        }
        // check collision probability: noisyxorbp
        for (auto &addr : res_noisyxorbp.first) {
          noisyxorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        noisyxorbp->lookupBTB(victim_addr, victim_addr,
                              SecurityDomain::DOM_VICTIM);
        for (auto &addr : res_noisyxorbp.first) {
          if (noisyxorbp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
              -1) {
            collision_stat[3]++;
            break;
          }
        }
        // check collision probability: lsbp
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
        // check collision probability: stbpu
        for (auto &addr : res_stbpu.first) {
          stbpu->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        stbpu->lookupBTB(victim_addr, victim_addr, SecurityDomain::DOM_VICTIM);
        for (auto &addr : res_stbpu.first) {
          if (stbpu->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) ==
              -1) {
            collision_stat[5]++;
            break;
          }
        }
        // check collision probability: hybp
        for (auto &addr : res_hybp.first) {
          hybp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER);
        }
        hybp->lookupBTB(victim_addr, victim_addr, SecurityDomain::DOM_VICTIM);
        for (auto &addr : res_hybp.first) {
          if (hybp->lookupBTB(addr, addr, SecurityDomain::DOM_ATTACKER) == -1) {
            collision_stat[6]++;
            break;
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