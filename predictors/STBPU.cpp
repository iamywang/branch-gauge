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
// date: 2024/12/03
// =============================================================================
// STBPU is proposed in DSN 2022
// Index  Encryption: PHT/pc+k0/hash, BTB/pc+k0/hash
// Src    Encryption: PHT/pc+k0/hash, BTB/pc+k0/hash
// Dest   Encryption: PHT/XOR/k1,     BTB/XOR/k1
// =============================================================================
#include "include/predictors/STBPU.hpp"

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "include/utils/Utils.hpp"

// init
void STBPU::initPHT(uint64_t counter_bits, uint64_t counter_nums,
                    uint64_t offset_pht) {
  this->counter_bits = counter_bits;
  this->counter_nums = counter_nums;
  this->offset_pht = offset_pht;
  PHT_valid.resize(counter_nums, 0);
  PHT_counter.resize(counter_nums, 0);
}

void STBPU::initBTB(uint64_t buffer_ways, uint64_t buffer_sets,
                    uint64_t offset_btb, ReplacementPolicy buffer_replacement) {
  this->buffer_ways = buffer_ways;
  this->buffer_sets = buffer_sets;
  this->offset_btb = offset_btb;
  this->buffer_replacement = buffer_replacement;
  BTB_valid.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, 0));
  BTB_src.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, -1));
  BTB_dest.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, -1));
  BTB_lru.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, 0));
}

// encryption and decryption
uint64_t STBPU::encrypt(uint64_t plain, uint64_t key) { return plain ^ key; }

uint64_t STBPU::decrypt(uint64_t cipher, uint64_t key) { return cipher ^ key; }

// get set and tag in PHT and BTB
uint64_t STBPU::getPHTSet(uint64_t pc, uint64_t domain) {
  // TODO: hash function (just simple XOR here)
  uint64_t plain = index_keys[domain] << addr_space | pc;
  return encrypt(plain, index_hashes[domain]) % counter_nums;
}

uint64_t STBPU::getBTBSet(uint64_t pc, uint64_t domain) {
  // TODO: hash function (just simple XOR here)
  uint64_t plain = index_keys[domain] << addr_space | pc;
  return encrypt(plain, index_hashes[domain]) % buffer_sets;
}

uint64_t STBPU::getBTBTag(uint64_t src, uint64_t domain) {
  // TODO: hash function (just simple XOR here)
  uint64_t plain = index_keys[domain] << addr_space | src;
  uint64_t cipher = encrypt(plain, index_hashes[domain]);
  return cipher >> (int)std::log2(buffer_sets);
}

uint64_t STBPU::getBTBDest(uint64_t dest, uint64_t domain) {
  return encrypt(dest, content_keys[domain]);
}

bool STBPU::lookupPHT(uint64_t pc, bool taken, uint64_t domain) {
  uint64_t index = getPHTSet(pc, domain);
  // get the highest bit
  uint64_t counter = decrypt(PHT_counter[index], content_keys[domain]) &
                     ((1ULL << counter_bits) - 1);
  bool prediction = counter >> (counter_bits - 1);
  if (PHT_valid[index] == 0) {
    updatePHT(pc, taken, domain);
    return false;
  }
  updatePHT(pc, taken, domain);
  return prediction == taken;
}

void STBPU::updatePHT(uint64_t pc, bool taken, uint64_t domain) {
  uint64_t index = getPHTSet(pc, domain);
  uint64_t counter = decrypt(PHT_counter[index], content_keys[domain]) &
                     ((1ULL << counter_bits) - 1);
  // check if the counter is valid
  if (PHT_valid[index] == 0) {
    PHT_valid[index] = 1;
    PHT_counter[index] =
        encrypt(taken, content_keys[domain]) & ((1ULL << counter_bits) - 1);
    return;
  }
  // update counter
  if (taken) {
    counter++;
  } else {
    counter--;
  }
  // check saturate
  if (counter == -1) {
    counter = 0;
  } else if (counter >= (1ULL << counter_bits)) {
    counter = (1ULL << counter_bits) - 1;
  }
  PHT_counter[index] =
      encrypt(counter, content_keys[domain]) & ((1ULL << counter_bits) - 1);
}

int STBPU::lookupBTB(uint64_t pc, uint64_t target, uint64_t domain) {
  uint64_t index = getBTBSet(pc, domain);
  // update LRU
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 1) {
      BTB_lru[index][i]++;
    }
  }
  // check if the target is in the buffer
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 1 &&
        BTB_src[index][i] == getBTBTag(pc, domain)) {
      // predicton state: $valid$
      if (BTB_dest[index][i] == getBTBDest(target, domain)) {
        updateBTB(pc, target, domain);
        return 1;
      }
      // predicton state: $mispredict$
      else {
        updateBTB(pc, target, domain);
        return 0;
      }
    }
  }
  // predicton state: $invalid$
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 0) {
      BTB_valid[index][i] = 1;
      BTB_src[index][i] = getBTBTag(pc, domain);
      updateBTB(pc, target, domain);
      return -1;
    }
  }
  // need replacement
  uint64_t max_lru = 0;
  if (buffer_replacement == ReplacementPolicy::REPL_LRU) {
    // LRU replacement
    for (uint64_t i = 0; i < buffer_ways; i++) {
      if (BTB_lru[index][i] > BTB_lru[index][max_lru]) {
        max_lru = i;
      }
    }
  } else if (buffer_replacement == ReplacementPolicy::REPL_RANDOM) {
    // Random replacement
    max_lru = rand() % buffer_ways;
  }
  BTB_src[index][max_lru] = getBTBTag(pc, domain);
  updateBTB(pc, target, domain);
  return -1;
}

void STBPU::updateBTB(uint64_t pc, uint64_t target, uint64_t domain) {
  uint64_t index = getBTBSet(pc, domain);
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 1 &&
        BTB_src[index][i] == getBTBTag(pc, domain)) {
      // update target
      BTB_dest[index][i] = getBTBDest(target, domain);
      // update LRU
      BTB_lru[index][i] = 0;
      return;
    }
  }
}

// regenerate branch address for test the correctness of the framework
uint64_t STBPU::regenerateTagAddr(uint64_t set, uint64_t tag, uint64_t domain) {
  // TODO: hash function (just simple XOR here)
  uint64_t cipher = (tag << (int)std::log2(buffer_sets)) | set;
  uint64_t plain = decrypt(cipher, index_hashes[domain]);
  return plain & ((1ULL << addr_space) - 1);
}

uint64_t STBPU::regenerateDestAddr(uint64_t dest, uint64_t domain) {
  return decrypt(dest, content_keys[domain]);
}

int STBPU::checkPHTSetCollision(uint64_t addr1, uint64_t domain1,
                                uint64_t addr2, uint64_t domain2) {
  return getPHTSet(addr1, domain1) == getPHTSet(addr2, domain2);
}