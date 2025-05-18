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
// date: 2024/12/01
// =============================================================================
// XOR-BP is proposed in DAC 2021
// Src   Encryption: PHT/XOR/k1, BTB/XOR/k1
// Dest  Encryption: PHT/XOR/k1, BTB/XOR/k1
// =============================================================================
#ifndef XOR_BP_HPP
#define XOR_BP_HPP
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "include/utils/Utils.hpp"

class XorBP {
 private:
  // address space
  uint64_t addr_space;

  // parameters for PHT
  uint64_t counter_bits;
  uint64_t counter_nums;
  uint64_t offset_pht;

  // parameters for BTB
  uint64_t buffer_ways;
  uint64_t buffer_sets;
  uint64_t offset_btb;
  ReplacementPolicy buffer_replacement;  // 0: LRU, 1: Random

  // data structures for PHT
  std::vector<uint64_t> PHT_valid;
  std::vector<uint64_t> PHT_counter;

  // data structures for BTB
  std::vector<std::vector<uint64_t>> BTB_valid;
  std::vector<std::vector<uint64_t>> BTB_src;
  std::vector<std::vector<uint64_t>> BTB_dest;
  std::vector<std::vector<uint64_t>> BTB_lru;

  // encryption keys
  std::vector<uint64_t> content_keys;

 public:
  XorBP(uint64_t addr_space = 32) : addr_space(addr_space) {
#ifdef RANDOM_KEY
    this->content_keys = {rand() & ((1ULL << addr_space) - 1),
                          rand() & ((1ULL << addr_space) - 1)};
#else
    this->content_keys = {EncryptionKey::KEY_0, EncryptionKey::KEY_1};
#endif
  }

  // init
  void initPHT(uint64_t counter_bits, uint64_t counter_nums,
               uint64_t offset_pht = 5);

  void initBTB(
      uint64_t buffer_ways, uint64_t buffer_sets, uint64_t offset_btb = 5,
      ReplacementPolicy buffer_replacement = ReplacementPolicy::REPL_LRU);

  // encryption and decryption
  uint64_t encrypt(uint64_t plain, uint64_t key);

  uint64_t decrypt(uint64_t cipher, uint64_t key);

  // get set and tag in PHT and BTB
  uint64_t getPHTSet(uint64_t pc, uint64_t domain);

  uint64_t getBTBSet(uint64_t pc, uint64_t domain);

  uint64_t getBTBTag(uint64_t src, uint64_t domain);

  uint64_t getBTBDest(uint64_t dest, uint64_t domain);

  bool lookupPHT(uint64_t pc, bool taken, uint64_t domain);

  void updatePHT(uint64_t pc, bool taken, uint64_t domain);

  int lookupBTB(uint64_t pc, uint64_t target, uint64_t domain);

  void updateBTB(uint64_t pc, uint64_t target, uint64_t domain);

  // regenerate branch address for test the correctness of the framework
  uint64_t regenerateTagAddr(uint64_t set, uint64_t tag, uint64_t domain);

  uint64_t regenerateDestAddr(uint64_t dest, uint64_t domain);

  int checkPHTSetCollision(uint64_t addr1, uint64_t domain1, uint64_t addr2,
                           uint64_t domain2);

  // reuse-based attack
  std::pair<uint64_t, uint64_t> PHTTiming(uint64_t num_loops,
                                          uint64_t counter_bits,
                                          uint64_t victim_addr);

  std::pair<uint64_t, uint64_t> PHTSpeculative(uint64_t num_loops,
                                               uint64_t counter_bits,
                                               uint64_t victim_addr);

  std::pair<uint64_t, uint64_t> BTBTiming(uint64_t num_loops,
                                          uint64_t victim_addr,
                                          uint64_t target_addr);

  std::pair<uint64_t, uint64_t> BTBSpeculative(uint64_t num_loops,
                                               uint64_t victim_addr,
                                               uint64_t target_addr,
                                               uint64_t covert_channel);

  // prune-based attack
  std::pair<std::vector<uint64_t>, uint64_t> BTBPrune(uint64_t num_loops,
                                                      uint64_t victim_addr,
                                                      uint64_t prune_size,
                                                      uint64_t eviction_size);

  // occupancy-based attack
  std::pair<std::vector<uint64_t>, uint64_t> PHTOccupancy(
      uint64_t num_loops, uint64_t counter_bits, uint64_t prune_size,
      uint64_t occupancy_size);

  std::pair<std::vector<uint64_t>, uint64_t> BTBOccupancy(
      uint64_t num_loops, uint64_t prune_size, uint64_t occupancy_size);
};
#endif