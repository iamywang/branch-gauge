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

class Exp1 {
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
  Exp1(uint64_t counter_bits, uint64_t counter_nums, uint64_t buffer_ways,
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

  // expriment: branch accesses
  std::vector<std::vector<uint64_t>> ReuseBranchAccess(uint64_t repeats,
                                                       uint64_t counter_bits) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp1: ReuseBranchAccess ==" << std::endl;
#endif
    // statistics
    std::vector<std::vector<uint64_t>> access_stats;
    // simulate the attack
    for (int i = 0; i < repeats; i++) {
#ifdef EVALUATION
      std::cout << "ReuseBranchAccess: " << i << std::endl;
#endif
      uint64_t num_loops = 1e9;
      uint64_t victim_addr = secrets[0];
      uint64_t target_addr = secrets[1];
      uint64_t covert_channel = secrets[2];
      std::vector<uint64_t> access_stat;
      // pht reuse attack
      std::pair<uint64_t, uint64_t> res_base =
          base_bpu->PHTTiming(num_loops, counter_bits, victim_addr);
      std::pair<uint64_t, uint64_t> res_bsup =
          bsup->PHTTiming(num_loops, 3, victim_addr);
      std::pair<uint64_t, uint64_t> res_xorbp =
          xorbp->PHTTiming(num_loops, counter_bits, victim_addr);
      std::pair<uint64_t, uint64_t> res_noisyxorbp =
          noisyxorbp->PHTTiming(num_loops, counter_bits, victim_addr);
      std::pair<uint64_t, uint64_t> res_lsbp = lsbp->PHTTiming(
          num_loops, counter_bits, victim_addr, attacker_pid, victim_pid);
      std::pair<uint64_t, uint64_t> res_stbpu =
          stbpu->PHTTiming(num_loops, counter_bits, victim_addr);
      std::pair<uint64_t, uint64_t> res_hybp =
          hybp->PHTTiming(num_loops, counter_bits, victim_addr);
      // save the statistics
      access_stat.push_back(res_base.second);
      access_stat.push_back(res_bsup.second);
      access_stat.push_back(res_xorbp.second);
      access_stat.push_back(res_noisyxorbp.second);
      access_stat.push_back(res_lsbp.second);
      access_stat.push_back(res_stbpu.second);
      access_stat.push_back(res_hybp.second);

      // btb timing attack
      res_base = base_bpu->BTBTiming(num_loops, victim_addr, target_addr);
      res_bsup = bsup->BTBTiming(num_loops, victim_addr, target_addr);
      res_xorbp = xorbp->BTBTiming(num_loops, victim_addr, target_addr);
      res_noisyxorbp =
          noisyxorbp->BTBTiming(num_loops, victim_addr, target_addr);
      res_lsbp =
          lsbp->BTBTiming(num_loops, victim_addr, target_addr, victim_pid);
      res_stbpu = stbpu->BTBTiming(num_loops, victim_addr, target_addr);
      res_hybp = hybp->BTBTiming(num_loops, victim_addr, target_addr);
      // save the statistics
      access_stat.push_back(res_base.second);
      access_stat.push_back(res_bsup.second);
      access_stat.push_back(res_xorbp.second);
      access_stat.push_back(res_noisyxorbp.second);
      access_stat.push_back(res_lsbp.second);
      access_stat.push_back(res_stbpu.second);
      access_stat.push_back(res_hybp.second);

      // btb speculative attack
      res_base = base_bpu->BTBSpeculative(num_loops, victim_addr, target_addr,
                                          covert_channel);
      res_bsup = bsup->BTBSpeculative(num_loops, victim_addr, target_addr,
                                      covert_channel);
      res_xorbp = xorbp->BTBSpeculative(num_loops, victim_addr, target_addr,
                                        covert_channel);
      res_noisyxorbp = noisyxorbp->BTBSpeculative(num_loops, victim_addr,
                                                  target_addr, covert_channel);
      res_lsbp = lsbp->BTBSpeculative(num_loops, victim_addr, target_addr,
                                      covert_channel, victim_pid);
      res_stbpu = stbpu->BTBSpeculative(num_loops, victim_addr, target_addr,
                                        covert_channel);
      res_hybp = hybp->BTBSpeculative(num_loops, victim_addr, target_addr,
                                      covert_channel);
      // save the statistics
      access_stat.push_back(res_base.second);
      access_stat.push_back(res_bsup.second);
      access_stat.push_back(res_xorbp.second);
      access_stat.push_back(res_noisyxorbp.second);
      access_stat.push_back(res_lsbp.second);
      access_stat.push_back(res_stbpu.second);
      access_stat.push_back(res_hybp.second);

      access_stats.push_back(access_stat);
      for (int j = 0; j < access_stat.size(); j++) {
        std::cerr << access_stat[j] << " ";
      }
      std::cerr << std::endl;
    }
    return access_stats;
  }

  // experiment: collision probability
  std::vector<std::vector<uint64_t>> ReuseCollisionRate(uint64_t repeats,
                                                        uint64_t counter_bits) {
    srand(time(NULL));
#ifdef EVALUATION
    std::cout << "== exp1: ReuseCollisionRate ==" << std::endl;
#endif
    // statistics
    std::vector<std::vector<uint64_t>> collision_stats;
    // simulate the attack
    std::vector<uint64_t> branch_accesses_num = {
        10000, 50000, 100000, 200000, 500000, 1000000, 10000000, 100000000};
    for (uint64_t num_accesses : branch_accesses_num) {
      NUMBER_MAX_BRANCHES = num_accesses;
#ifdef EVALUATION
      std::cout << "ReuseCollisionRate: " << num_accesses << std::endl;
#endif
      // statistics
      std::vector<uint64_t> pht_reuse_stat(7, 0);
      std::vector<uint64_t> btb_timing_stat(7, 0);
      std::vector<uint64_t> btb_spec_stat(7, 0);
      uint64_t num_loops = 1e9;
      uint64_t victim_addr = secrets[0];
      uint64_t target_addr = secrets[1];
      uint64_t covert_channel = secrets[2];
      // PHT reuse attack
      for (int i = 0; i < repeats; i++) {
        std::pair<uint64_t, uint64_t> res_base =
            base_bpu->PHTTiming(num_loops, counter_bits, victim_addr);
        std::pair<uint64_t, uint64_t> res_bsup =
            bsup->PHTTiming(num_loops, 3, victim_addr);
        std::pair<uint64_t, uint64_t> res_xorbp =
            xorbp->PHTTiming(num_loops, counter_bits, victim_addr);
        std::pair<uint64_t, uint64_t> res_noisyxorbp =
            noisyxorbp->PHTTiming(num_loops, counter_bits, victim_addr);
        std::pair<uint64_t, uint64_t> res_lsbp = lsbp->PHTTiming(
            num_loops, counter_bits, victim_addr, attacker_pid, victim_pid);
        std::pair<uint64_t, uint64_t> res_stbpu =
            stbpu->PHTTiming(num_loops, counter_bits, victim_addr);
        std::pair<uint64_t, uint64_t> res_hybp =
            hybp->PHTTiming(num_loops, counter_bits, victim_addr);
        // save the statistics
        if (res_base.second <= num_accesses && res_base.first != -1) {
          pht_reuse_stat[0]++;
        }
        if (res_bsup.second <= num_accesses && res_bsup.first != -1) {
          pht_reuse_stat[1]++;
        }
        if (res_xorbp.second <= num_accesses && res_xorbp.first != -1) {
          pht_reuse_stat[2]++;
        }
        if (res_noisyxorbp.second <= num_accesses &&
            res_noisyxorbp.first != -1) {
          pht_reuse_stat[3]++;
        }
        if (res_lsbp.second <= num_accesses && res_lsbp.first != -1) {
          pht_reuse_stat[4]++;
        }
        if (res_stbpu.second <= num_accesses && res_stbpu.first != -1) {
          pht_reuse_stat[5]++;
        }
        if (res_hybp.second <= num_accesses && res_hybp.first != -1) {
          pht_reuse_stat[6]++;
        }
      }
      // dump the statistics
      collision_stats.push_back(pht_reuse_stat);
      for (int j = 0; j < pht_reuse_stat.size(); j++) {
        std::cerr << pht_reuse_stat[j] << " ";
      }
      // BTB timing attack
      for (int i = 0; i < repeats; i++) {
        std::pair<uint64_t, uint64_t> res_base =
            base_bpu->BTBTiming(num_loops, victim_addr, target_addr);
        std::pair<uint64_t, uint64_t> res_bsup =
            bsup->BTBTiming(num_loops, victim_addr, target_addr);
        std::pair<uint64_t, uint64_t> res_xorbp =
            xorbp->BTBTiming(num_loops, victim_addr, target_addr);
        std::pair<uint64_t, uint64_t> res_noisyxorbp =
            noisyxorbp->BTBTiming(num_loops, victim_addr, target_addr);
        std::pair<uint64_t, uint64_t> res_lsbp =
            lsbp->BTBTiming(num_loops, victim_addr, target_addr, victim_pid);
        std::pair<uint64_t, uint64_t> res_stbpu =
            stbpu->BTBTiming(num_loops, victim_addr, target_addr);
        std::pair<uint64_t, uint64_t> res_hybp =
            hybp->BTBTiming(num_loops, victim_addr, target_addr);
        // save the statistics
        if (res_base.second <= num_accesses && res_base.first != -1) {
          btb_timing_stat[0]++;
        }
        if (res_bsup.second <= num_accesses && res_bsup.first != -1) {
          btb_timing_stat[1]++;
        }
        if (res_xorbp.second <= num_accesses && res_xorbp.first != -1) {
          btb_timing_stat[2]++;
        }
        if (res_noisyxorbp.second <= num_accesses &&
            res_noisyxorbp.first != -1) {
          btb_timing_stat[3]++;
        }
        if (res_lsbp.second <= num_accesses && res_lsbp.first != -1) {
          btb_timing_stat[4]++;
        }
        if (res_stbpu.second <= num_accesses && res_stbpu.first != -1) {
          btb_timing_stat[5]++;
        }
        if (res_hybp.second <= num_accesses && res_hybp.first != -1) {
          btb_timing_stat[6]++;
        }
      }
      // dump the statistics
      collision_stats.push_back(btb_timing_stat);
      for (int j = 0; j < btb_timing_stat.size(); j++) {
        std::cerr << btb_timing_stat[j] << " ";
      }
      // BTB speculative attack
      for (int i = 0; i < repeats; i++) {
        std::pair<uint64_t, uint64_t> res_base = base_bpu->BTBSpeculative(
            num_loops, victim_addr, target_addr, covert_channel);
        std::pair<uint64_t, uint64_t> res_bsup = bsup->BTBSpeculative(
            num_loops, victim_addr, target_addr, covert_channel);
        std::pair<uint64_t, uint64_t> res_xorbp = xorbp->BTBSpeculative(
            num_loops, victim_addr, target_addr, covert_channel);
        std::pair<uint64_t, uint64_t> res_noisyxorbp =
            noisyxorbp->BTBSpeculative(num_loops, victim_addr, target_addr,
                                       covert_channel);
        std::pair<uint64_t, uint64_t> res_lsbp = lsbp->BTBSpeculative(
            num_loops, victim_addr, target_addr, covert_channel, victim_pid);
        std::pair<uint64_t, uint64_t> res_stbpu = stbpu->BTBSpeculative(
            num_loops, victim_addr, target_addr, covert_channel);
        std::pair<uint64_t, uint64_t> res_hybp = hybp->BTBSpeculative(
            num_loops, victim_addr, target_addr, covert_channel);
        // save the statistics
        if (res_base.second <= num_accesses && res_base.first != -1) {
          btb_spec_stat[0]++;
        }
        if (res_bsup.second <= num_accesses && res_bsup.first != -1) {
          btb_spec_stat[1]++;
        }
        if (res_xorbp.second <= num_accesses && res_xorbp.first != -1) {
          btb_spec_stat[2]++;
        }
        if (res_noisyxorbp.second <= num_accesses &&
            res_noisyxorbp.first != -1) {
          btb_spec_stat[3]++;
        }
        if (res_lsbp.second <= num_accesses && res_lsbp.first != -1) {
          btb_spec_stat[4]++;
        }
        if (res_stbpu.second <= num_accesses && res_stbpu.first != -1) {
          btb_spec_stat[5]++;
        }
        if (res_hybp.second <= num_accesses && res_hybp.first != -1) {
          btb_spec_stat[6]++;
        }
      }
      // dump the statistics
      collision_stats.push_back(btb_spec_stat);
      for (int j = 0; j < btb_spec_stat.size(); j++) {
        std::cerr << btb_spec_stat[j] << " ";
      }
      std::cerr << std::endl;
    }
    return collision_stats;
  }
};