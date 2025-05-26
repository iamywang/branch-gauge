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
// date: 2024/12/17
// =============================================================================
// LS-BP is proposed in ASP-DAC 2022
// Index  Encryption: PHT/PID+XOR/k0, BTB/PID+XOR/k0
// =============================================================================
#include "include/predictors/LSBP.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "include/utils/Utils.hpp"

// reuse-based attack
std::pair<uint64_t, uint64_t> LSBP::PHTTiming(uint64_t num_loops,
                                              uint64_t counter_bits,
                                              uint64_t victim_addr,
                                              uint64_t attacker_pid,
                                              uint64_t victim_pid) {
#ifdef ATTACK
  std::cout << "== PHTTiming ==" << std::endl;
#endif
  uint64_t total_access = 0;
  std::vector<uint64_t> gen_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (gen_set.size() < num_loops && total_access < NUMBER_MAX_BRANCHES) {
#else
  while (gen_set.size() < num_loops) {
#endif
    uint64_t attacker_addr = rand() & ((1ULL << addr_space) - 1);
    // if (std::find(gen_set.begin(), gen_set.end(), attacker_addr) !=
    //     gen_set.end()) {
    //   continue;
    // }
    gen_set.push_back(attacker_addr);
    uint64_t total_check = std::exp2(counter_bits) / 2;
    for (uint64_t i = 0; i < total_check; i++) {
      // initial state to $valid$
      for (uint64_t j = 0; j < total_check; j++) {
        this->lookupPHT(victim_addr, true, victim_pid,
                        SecurityDomain::DOM_VICTIM);
        total_access++;
      }
      // train the PHT to $mispredict$
      for (uint64_t j = 0; j < total_check; j++) {
        this->lookupPHT(attacker_addr, true, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      for (uint64_t j = 0; j <= i; j++) {
        this->lookupPHT(attacker_addr, false, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      // victim access
      uint64_t timing = this->lookupPHT(victim_addr, true, victim_pid,
                                        SecurityDomain::DOM_VICTIM);
      total_access++;

#ifdef DEBUG
      if (this->getPHTSet(attacker_addr, attacker_pid,
                          SecurityDomain::DOM_ATTACKER) ==
          this->getPHTSet(victim_addr, victim_pid,
                          SecurityDomain::DOM_VICTIM)) {
        std::cout << "== only for debug ==" << std::endl;
        std::cout << "attacker_addr: " << std::hex << attacker_addr
                  << std::endl;
        std::cout << "victim_addr: " << std::hex << victim_addr << std::endl;
        std::cout << "== only for debug ==" << std::endl;
      }
#endif

      // check the timing $hit$ or $miss$
      if (timing == false) {
#ifdef ATTACK
        std::cout << std::dec << "current_loop: " << gen_set.size()
                  << std::endl;
        std::cout << std::dec << "total_access: " << total_access << std::endl;
        std::cout << std::hex << "attacker_addr: " << attacker_addr
                  << std::endl;
#endif
        return std::make_pair(attacker_addr, total_access);
      }
    }
  }
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << gen_set.size() << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::hex << "attacker_addr: failed" << std::endl;
#endif
  return std::make_pair(-1, total_access);
}

std::pair<uint64_t, uint64_t> LSBP::PHTSpeculative(uint64_t num_loops,
                                                   uint64_t counter_bits,
                                                   uint64_t victim_addr,
                                                   uint64_t attacker_pid,
                                                   uint64_t victim_pid) {
#ifdef ATTACK
  std::cout << "== PHTSpeculative ==" << std::endl;
#endif
  uint64_t total_access = 0;
  std::vector<uint64_t> gen_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (gen_set.size() < num_loops && total_access < NUMBER_MAX_BRANCHES) {
#else
  while (gen_set.size() < num_loops) {
#endif
    uint64_t attacker_addr = rand() & ((1ULL << addr_space) - 1);
    // if (std::find(gen_set.begin(), gen_set.end(), attacker_addr) !=
    //     gen_set.end()) {
    //   continue;
    // }
    gen_set.push_back(attacker_addr);
    uint64_t total_check = std::exp2(counter_bits) / 2;
    for (uint64_t i = 0; i < total_check; i++) {
      // initial state to $valid$
      for (uint64_t j = 0; j < total_check; j++) {
        this->lookupPHT(victim_addr, true, victim_pid,
                        SecurityDomain::DOM_VICTIM);
        total_access++;
      }
      // train the PHT to $mispredict$
      for (uint64_t j = 0; j < total_check; j++) {
        this->lookupPHT(attacker_addr, true, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      for (uint64_t j = 0; j <= i; j++) {
        this->lookupPHT(attacker_addr, false, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      // victim access
      uint64_t timing = this->lookupPHT(victim_addr, true, victim_pid,
                                        SecurityDomain::DOM_VICTIM);
      total_access++;

#ifdef DEBUG
      if (this->getPHTSet(attacker_addr, attacker_pid,
                          SecurityDomain::DOM_ATTACKER) ==
          this->getPHTSet(victim_addr, victim_pid,
                          SecurityDomain::DOM_VICTIM)) {
        std::cout << "== only for debug ==" << std::endl;
        std::cout << "attacker_addr: " << std::hex << attacker_addr
                  << std::endl;
        std::cout << "victim_addr: " << std::hex << victim_addr << std::endl;
        std::cout << "== only for debug ==" << std::endl;
      }
#endif

      // check the timing $hit$ or $miss$
      if (timing == false) {
#ifdef ATTACK
        std::cout << std::dec << "current_loop: " << gen_set.size()
                  << std::endl;
        std::cout << std::dec << "total_access: " << total_access << std::endl;
        std::cout << std::hex << "attacker_addr: " << attacker_addr
                  << std::endl;
#endif
        return std::make_pair(attacker_addr, total_access);
      }
    }
  }
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << gen_set.size() << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::hex << "attacker_addr: failed" << std::endl;
#endif
  return std::make_pair(-1, total_access);
}

std::pair<uint64_t, uint64_t> LSBP::BTBTiming(uint64_t num_loops,
                                              uint64_t victim_addr,
                                              uint64_t target_addr,
                                              uint64_t victim_pid) {
#ifdef ATTACK
  std::cout << "== BTBTiming ==" << std::endl;
#endif
  uint64_t total_access = 0;
  std::vector<uint64_t> gen_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (gen_set.size() < num_loops && total_access < NUMBER_MAX_BRANCHES) {
#else
  while (gen_set.size() < num_loops) {
#endif
    uint64_t attacker_addr = victim_addr;
    uint64_t attacker_target = -1;
    uint64_t attacker_pid = rand() & ((1ULL << addr_space) - 1);
#ifdef RANDOM_KEY
    this->index_keys = {rand() & ((1ULL << addr_space) - 1),
                        rand() & ((1ULL << addr_space) - 1)};
#else
    this->index_keys = {EncryptionKey::KEY_0, EncryptionKey::KEY_1};
#endif
    // check if the attacker address is in the buffer or same as the victim
    // if (std::find(gen_set.begin(), gen_set.end(), attacker_pid) !=
    //     gen_set.end()) {
    //   continue;
    // }
    if (attacker_pid == victim_pid) {
      continue;
    }
    gen_set.push_back(attacker_pid);
    // initial state to $valid$
    this->lookupBTB(victim_addr, target_addr, victim_pid,
                    SecurityDomain::DOM_VICTIM);
    total_access++;
    // train the BTB to $mispredict$
    this->lookupBTB(attacker_addr, attacker_target, attacker_pid,
                    SecurityDomain::DOM_ATTACKER);
    total_access++;
    // victim access
    uint64_t timing = this->lookupBTB(victim_addr, target_addr, victim_pid,
                                      SecurityDomain::DOM_VICTIM);
    total_access++;

#ifdef DEBUG
    int set_collision =
        this->getBTBSet(attacker_addr, attacker_pid,
                        SecurityDomain::DOM_ATTACKER) ==
        this->getBTBSet(victim_addr, victim_pid, SecurityDomain::DOM_VICTIM);
    int target_collision =
        this->getBTBTag(attacker_addr, SecurityDomain::DOM_ATTACKER) ==
        this->getBTBTag(victim_addr, SecurityDomain::DOM_VICTIM);
    if (set_collision && target_collision) {
      std::cout << "== only for debug ==" << std::endl;
      std::cout << "attacker_pid: " << std::hex << attacker_pid << std::endl;
      std::cout << "victim_pid: " << std::hex << victim_pid << std::endl;
      std::cout << "attacker_addr: " << std::hex << attacker_addr << std::endl;
      std::cout << "victim_addr: " << std::hex << victim_addr << std::endl;
      std::cout << "== only for debug ==" << std::endl;
    }
#endif

    // check the timing $hit$ or $miss$
    if (timing == false) {
#ifdef ATTACK
      std::cout << std::dec << "current_loop: " << gen_set.size() << std::endl;
      std::cout << std::dec << "total_access: " << total_access << std::endl;
      std::cout << std::hex << "attacker_pid: " << attacker_pid << std::endl;
      std::cout << std::hex << "attacker_addr: " << attacker_addr << std::endl;
#endif
      return std::make_pair(attacker_addr, total_access);
    }
  }
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << gen_set.size() << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::hex << "attacker_pid: failed" << std::endl;
  std::cout << std::hex << "attacker_addr: failed" << std::endl;
#endif
  return std::make_pair(-1, total_access);
}

std::pair<uint64_t, uint64_t> LSBP::BTBSpeculative(uint64_t num_loops,
                                                   uint64_t victim_addr,
                                                   uint64_t target_addr,
                                                   uint64_t covert_channel,
                                                   uint64_t victim_pid) {
#ifdef ATTACK
  std::cout << "== BTBSpeculative ==" << std::endl;
#endif
  uint64_t total_access = 0;
  std::vector<uint64_t> gen_set;
  std::vector<uint64_t> tar_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (gen_set.size() + tar_set.size() < num_loops &&
         total_access < NUMBER_MAX_BRANCHES) {
#else
  while (gen_set.size() + tar_set.size() < num_loops) {
#endif
    uint64_t attacker_addr = victim_addr;
    uint64_t attacker_target = -1;
    uint64_t attacker_pid = rand() & ((1ULL << addr_space) - 1);
#ifdef RANDOM_KEY
    this->index_keys = {rand() & ((1ULL << addr_space) - 1),
                        rand() & ((1ULL << addr_space) - 1)};
#else
    this->index_keys = {EncryptionKey::KEY_0, EncryptionKey::KEY_1};
#endif
    // check if the attacker address is in the buffer or same as the victim
    // if (std::find(gen_set.begin(), gen_set.end(), attacker_pid) !=
    //     gen_set.end()) {
    //   continue;
    // }
    if (attacker_pid == victim_pid) {
      continue;
    }
    gen_set.push_back(attacker_pid);
    // initial state to $valid$
    this->lookupBTB(victim_addr, target_addr, victim_pid,
                    SecurityDomain::DOM_VICTIM);
    total_access++;
    // train the BTB to $mispredict$
    this->lookupBTB(attacker_addr, attacker_target, attacker_pid,
                    SecurityDomain::DOM_ATTACKER);
    total_access++;
    // victim access
    uint64_t timing = this->lookupBTB(victim_addr, target_addr, victim_pid,
                                      SecurityDomain::DOM_VICTIM);
    total_access++;

#ifdef DEBUG
    int set_collision =
        this->getBTBSet(attacker_addr, attacker_pid,
                        SecurityDomain::DOM_ATTACKER) ==
        this->getBTBSet(victim_addr, victim_pid, SecurityDomain::DOM_VICTIM);
    int target_collision =
        this->getBTBTag(attacker_addr, SecurityDomain::DOM_ATTACKER) ==
        this->getBTBTag(victim_addr, SecurityDomain::DOM_VICTIM);
    if (set_collision && target_collision) {
      std::cout << "== only for debug ==" << std::endl;
      std::cout << "attacker_addr: " << std::hex << attacker_addr << std::endl;
      std::cout << "victim_addr: " << std::hex << victim_addr << std::endl;
      std::cout << "== only for debug ==" << std::endl;
    }
#endif

    // check the timing $hit$ or $miss$
    if (timing == false) {
#ifdef ATTACK
      std::cout << std::dec
                << "current_loop: " << gen_set.size() + tar_set.size()
                << std::endl;
      std::cout << std::dec << "total_access: " << total_access << std::endl;
      std::cout << std::hex << "attacker_pid: " << attacker_pid << std::endl;
      std::cout << std::hex << "attacker_addr: " << attacker_addr << std::endl;
#endif
// find covert channel
#ifdef LIMITED_BRANCH_ACCESS
      while (gen_set.size() + tar_set.size() < num_loops &&
             total_access < NUMBER_MAX_BRANCHES) {
#else
      while (gen_set.size() + tar_set.size() < num_loops) {
#endif
        uint64_t attacker_target = covert_channel;
        // if (std::find(tar_set.begin(), tar_set.end(), attacker_target) !=
        //     tar_set.end()) {
        //   continue;
        // }
        tar_set.push_back(attacker_target);
        this->lookupBTB(attacker_addr, attacker_target, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
        // check the covert channel $hit$ or $miss$
        total_access++;
        if (this->regenerateDestAddr(attacker_target, victim_pid,
                                     SecurityDomain::DOM_VICTIM) ==
            covert_channel) {
#ifdef ATTACK
          std::cout << std::dec
                    << "current_loop: " << gen_set.size() + tar_set.size()
                    << std::endl;
          std::cout << std::dec << "total_access: " << total_access
                    << std::endl;
          std::cout << std::hex << "attacker_pid: " << attacker_pid
                    << std::endl;
          std::cout << std::hex << "covert_channel: " << attacker_target
                    << std::endl;
#endif
          return std::make_pair(attacker_addr, total_access);
        }
      }
    }
  }
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << gen_set.size() + tar_set.size()
            << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::hex << "attacker_pid: failed" << std::endl;
  std::cout << std::hex << "attacker_addr: failed" << std::endl;
  std::cout << std::hex << "covert_channel: failed" << std::endl;
#endif
  return std::make_pair(-1, total_access);
}

// prune-based attack
std::pair<std::vector<uint64_t>, uint64_t> LSBP::BTBPrune(
    uint64_t num_loops, uint64_t victim_addr, uint64_t prune_size,
    uint64_t eviction_size, uint64_t attacker_pid, uint64_t victim_pid) {
#ifdef ATTACK
  std::cout << "== BTBPrune ==" << std::endl;
#endif
  uint64_t current_loop = 0;
  uint64_t total_access = 0;
  std::vector<uint64_t> prune_set;
  std::vector<uint64_t> eviction_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (current_loop < num_loops && eviction_set.size() < eviction_size &&
         total_access < NUMBER_MAX_BRANCHES) {
#else
  while (current_loop < num_loops && eviction_set.size() < eviction_size) {
#endif
    uint64_t attacker_addr = rand() & ((1ULL << addr_space) - 1);
    // attacker addr should not be in the prune set and eviction set
    // if (std::find(prune_set.begin(), prune_set.end(), attacker_addr) !=
    //     prune_set.end()) {
    //   continue;
    // }
    if (std::find(eviction_set.begin(), eviction_set.end(), attacker_addr) !=
        eviction_set.end()) {
      continue;
    }
    prune_set.push_back(attacker_addr);
    // generate the prune set with the size of $prune_size$
    if (prune_set.size() < prune_size) {
      current_loop++;
      continue;
    }
    // remove self conflict
    int self_conflict = 1;
    while (self_conflict != 0) {
      // initial prune set state to $valid$
      for (uint64_t &addr : prune_set) {
        this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      // check the prune set $hit$ or $miss$
      int collision = 0;
      for (uint64_t &addr : prune_set) {
        uint64_t timing = this->lookupBTB(addr, -1, attacker_pid,
                                          SecurityDomain::DOM_ATTACKER);
        total_access++;
        if (timing == -1 && prune_set.size() > buffer_ways) {
          collision++;
          prune_set.erase(std::remove(prune_set.begin(), prune_set.end(), addr),
                          prune_set.end());
        }
      }
      self_conflict = collision;
    }
    // victim access
    this->lookupBTB(victim_addr, -1, victim_pid, SecurityDomain::DOM_VICTIM);
    total_access++;
    // check the prune set $hit$ or $miss$
    for (uint64_t &addr : prune_set) {
      uint64_t timing =
          this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
      total_access++;
      if (timing == -1) {
#ifdef DEBUG
        std::cout << "== only for debug ==" << std::endl;
        std::cout << "collision addr: " << addr << std::endl;
        std::cout << "attacker set: "
                  << this->getBTBSet(addr, attacker_pid,
                                     SecurityDomain::DOM_ATTACKER)
                  << std::endl;
        std::cout << "victim set: "
                  << this->getBTBSet(victim_addr, victim_pid,
                                     SecurityDomain::DOM_VICTIM)
                  << std::endl;
        std::cout << "== only for debug ==" << std::endl;
#endif
        eviction_set.push_back(addr);
        prune_set.erase(std::remove(prune_set.begin(), prune_set.end(), addr),
                        prune_set.end());
      }
    }
    prune_set.clear();
    current_loop++;
  }
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << current_loop << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::dec << "eviction_set: " << eviction_set.size() << std::endl;
#endif
  return std::make_pair(eviction_set, total_access);
}

// occupancy-based attack
std::pair<std::vector<uint64_t>, uint64_t> LSBP::PHTOccupancy(
    uint64_t num_loops, uint64_t counter_bits, uint64_t prune_size,
    uint64_t occupancy_size, uint64_t attacker_pid) {
#ifdef ATTACK
  std::cout << "== PHTOccupancy ==" << std::endl;
#endif
  uint64_t current_loop = 0;
  uint64_t total_access = 0;
  std::vector<uint64_t> prune_set;
  std::vector<uint64_t> occupancy_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (current_loop < num_loops && occupancy_set.size() < occupancy_size &&
         total_access < NUMBER_MAX_BRANCHES) {
#else
  while (current_loop < num_loops && occupancy_set.size() < occupancy_size) {
#endif
    uint64_t attacker_addr = rand() & ((1ULL << addr_space) - 1);
    // attacker addr should not be in the prune set and occupancy set
    // if (std::find(prune_set.begin(), prune_set.end(), attacker_addr) !=
    //     prune_set.end()) {
    //   continue;
    // }
    if (std::find(occupancy_set.begin(), occupancy_set.end(), attacker_addr) !=
        occupancy_set.end()) {
      continue;
    }
    prune_set.push_back(attacker_addr);
    // generate the prune set with the size of $prune_size$
    if (prune_set.size() < prune_size) {
      current_loop++;
      continue;
    }
    uint64_t total_check = std::exp2(counter_bits) / 2;
    // remove self conflict in the prune set
    auto checkTwoAddrConflict = [&](uint64_t addr1, uint64_t addr2) {
      for (uint64_t i = 0; i < total_check; i++) {
        this->lookupPHT(addr1, false, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      for (uint64_t i = 0; i < total_check; i++) {
        this->lookupPHT(addr2, true, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      uint64_t timing = this->lookupPHT(addr1, false, attacker_pid,
                                        SecurityDomain::DOM_ATTACKER);
      total_access++;
      return !timing;
    };
    int self_confilct = 1;
    while (self_confilct != 0) {
      int collision = 0;
      for (uint64_t idx_i = 0; idx_i < prune_set.size(); idx_i++) {
        for (uint64_t idx_j = idx_i + 1; idx_j < prune_set.size(); idx_j++) {
          if (checkTwoAddrConflict(prune_set[idx_i], prune_set[idx_j]) ==
              true) {
            prune_set.erase(prune_set.begin() + idx_j);
            collision++;
          }
        }
      }
      self_confilct = collision;
    }
    // initial prune set state to $valid$
    for (uint64_t &addr : prune_set) {
      for (uint64_t i = 0; i < total_check; i++) {
        this->lookupPHT(addr, true, attacker_pid, SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
    }
    // access the occupancy set
    for (uint64_t &addr : occupancy_set) {
      for (uint64_t i = 0; i < total_check; i++) {
        this->lookupPHT(addr, false, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
    }
    // check the addr $hit$ or $miss$
    for (uint64_t &addr : prune_set) {
      uint64_t timing = this->lookupPHT(addr, true, attacker_pid,
                                        SecurityDomain::DOM_ATTACKER);
      total_access++;
      if (timing == true) {
        occupancy_set.push_back(addr);
      }
    }
    prune_set.clear();
    current_loop++;
  }
#ifdef DEBUG
  uint64_t total_check = std::exp2(counter_bits) / 2;
  for (auto &addr : occupancy_set) {
    for (uint64_t i = 0; i < total_check; i++) {
      this->lookupPHT(addr, false, attacker_pid, SecurityDomain::DOM_ATTACKER);
    }
    for (auto &addr2 : occupancy_set) {
      if (addr == addr2) {
        continue;
      }
      for (uint64_t i = 0; i < total_check; i++) {
        this->lookupPHT(addr2, true, attacker_pid,
                        SecurityDomain::DOM_ATTACKER);
      }
      // check the addr $hit$ or $miss$
      uint64_t timing = this->lookupPHT(addr, false, attacker_pid,
                                        SecurityDomain::DOM_ATTACKER);
      if (timing == false) {
        std::cout << "== only for debug ==" << std::endl;
        std::cout << "not satisfy occupancy set" << std::endl;
        std::cout << "== only for debug ==" << std::endl;
      }
    }
  }
#endif
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << current_loop << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::dec << "occupancy_set: " << occupancy_set.size()
            << std::endl;
#endif
  return std::make_pair(occupancy_set, total_access);
}

std::pair<std::vector<uint64_t>, uint64_t> LSBP::BTBOccupancy(
    uint64_t num_loops, uint64_t prune_size, uint64_t occupancy_size,
    uint64_t attacker_pid) {
#ifdef ATTACK
  std::cout << "== BTBOccupancy ==" << std::endl;
#endif
  uint64_t current_loop = 0;
  uint64_t total_access = 0;
  std::vector<uint64_t> prune_set;
  std::vector<uint64_t> occupancy_set;
#ifdef LIMITED_BRANCH_ACCESS
  while (current_loop < num_loops && occupancy_set.size() < occupancy_size &&
         total_access < NUMBER_MAX_BRANCHES) {
#else
  while (current_loop < num_loops && occupancy_set.size() < occupancy_size) {
#endif
    uint64_t attacker_addr = rand() & ((1ULL << addr_space) - 1);
    // attacker addr should not be in the prune set and occupancy set
    // if (std::find(prune_set.begin(), prune_set.end(), attacker_addr) !=
    //     prune_set.end()) {
    //   continue;
    // }
    if (std::find(occupancy_set.begin(), occupancy_set.end(), attacker_addr) !=
        occupancy_set.end()) {
      continue;
    }
    prune_set.push_back(attacker_addr);
    // generate the prune set with the size of $prune_size$
    if (prune_set.size() < prune_size) {
      current_loop++;
      continue;
    }
    // remove self conflict
    int self_conflict = 1;
    while (self_conflict != 0) {
      // initial prune set state to $valid$
      for (uint64_t &addr : prune_set) {
        this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
        total_access++;
      }
      // check the prune set $hit$ or $miss$
      int collision = 0;
      for (uint64_t &addr : prune_set) {
        uint64_t timing = this->lookupBTB(addr, -1, attacker_pid,
                                          SecurityDomain::DOM_ATTACKER);
        total_access++;
        if (timing == -1) {
          collision++;
          prune_set.erase(std::remove(prune_set.begin(), prune_set.end(), addr),
                          prune_set.end());
        }
      }
      self_conflict = collision;
    }
    // check conflict with the occupancy set
    for (uint64_t &addr : occupancy_set) {
      this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
      total_access++;
    }
    // check the prune set $hit$ or $miss$
    for (uint64_t &addr : prune_set) {
      uint64_t timing =
          this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
      total_access++;
      if (timing == 1) {
        occupancy_set.push_back(addr);
      }
    }
    prune_set.clear();
    current_loop++;
  }
#ifdef DEBUG
  for (auto &addr : occupancy_set) {
    this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
  }
  for (auto &addr : occupancy_set) {
    uint64_t timing =
        this->lookupBTB(addr, -1, attacker_pid, SecurityDomain::DOM_ATTACKER);
    if (timing == -1) {
      std::cout << "== only for debug ==" << std::endl;
      std::cout << "not satisfy occupancy set" << std::endl;
      std::cout << "== only for debug ==" << std::endl;
    }
  }
#endif
#ifdef ATTACK
  std::cout << std::dec << "current_loop: " << current_loop << std::endl;
  std::cout << std::dec << "total_access: " << total_access << std::endl;
  std::cout << std::dec << "occupancy_set: " << occupancy_set.size()
            << std::endl;
#endif
  return std::make_pair(occupancy_set, total_access);
}