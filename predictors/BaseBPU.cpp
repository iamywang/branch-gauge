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
// date: 2024/11/30
// =============================================================================
#include "include/predictors/BaseBPU.hpp"

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "include/utils/Utils.hpp"

// init
void BaseBPU::initPHT(uint64_t counter_bits, uint64_t counter_nums,
                      uint64_t offset_pht) {
  this->counter_bits = counter_bits;
  this->counter_nums = counter_nums;
  this->offset_pht = offset_pht;
  PHT_valid.resize(counter_nums, 0);
  PHT_counter.resize(counter_nums, 0);
}

void BaseBPU::initBTB(uint64_t buffer_ways, uint64_t buffer_sets,
                      uint64_t offset_btb,
                      ReplacementPolicy buffer_replacement) {
  this->buffer_ways = buffer_ways;
  this->buffer_sets = buffer_sets;
  this->offset_btb = offset_btb;
  this->buffer_replacement = buffer_replacement;
  BTB_valid.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, 0));
  BTB_src.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, -1));
  BTB_dest.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, -1));
  BTB_lru.resize(buffer_sets, std::vector<uint64_t>(buffer_ways, 0));
}

// get set and tag in PHT and BTB
uint64_t BaseBPU::getPHTSet(uint64_t pc) {
  return (pc >> offset_pht) % counter_nums;
}

uint64_t BaseBPU::getBTBSet(uint64_t pc) {
  return (pc >> offset_btb) % buffer_sets;
}

uint64_t BaseBPU::getBTBTag(uint64_t src) {
  return src >> offset_btb >> (int)std::log2(buffer_sets);
}

uint64_t BaseBPU::getBTBDest(uint64_t dest) { return dest; }

bool BaseBPU::lookupPHT(uint64_t pc, bool taken) {
  uint64_t index = getPHTSet(pc);
  // get the highest bit
  bool prediction = PHT_counter[index] >> (counter_bits - 1);
  if (PHT_valid[index] == 0) {
    updatePHT(pc, taken);
    return false;
  }
  updatePHT(pc, taken);
  return prediction == taken;
}

void BaseBPU::updatePHT(uint64_t pc, bool taken) {
  uint64_t index = getPHTSet(pc);
  uint64_t counter = PHT_counter[index];
  // check if the counter is valid
  if (PHT_valid[index] == 0) {
    PHT_valid[index] = 1;
    PHT_counter[index] = taken;
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
  PHT_counter[index] = counter;
}

int BaseBPU::lookupBTB(uint64_t pc, uint64_t target) {
  uint64_t index = getBTBSet(pc);
  // update LRU
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 1) {
      BTB_lru[index][i]++;
    }
  }
  // check if the target is in the buffer
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 1 && BTB_src[index][i] == getBTBTag(pc)) {
      // predicton state: $valid$
      if (BTB_dest[index][i] == getBTBDest(target)) {
        updateBTB(pc, target);
        return 1;
      }
      // predicton state: $mispredict$
      else {
        updateBTB(pc, target);
        return 0;
      }
    }
  }
  // predicton state: $invalid$
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 0) {
      BTB_valid[index][i] = 1;
      BTB_src[index][i] = getBTBTag(pc);
      updateBTB(pc, target);
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
  BTB_src[index][max_lru] = getBTBTag(pc);
  updateBTB(pc, target);
  return -1;
}

void BaseBPU::updateBTB(uint64_t pc, uint64_t target) {
  uint64_t index = getBTBSet(pc);
  for (uint64_t i = 0; i < buffer_ways; i++) {
    if (BTB_valid[index][i] == 1 && BTB_src[index][i] == getBTBTag(pc)) {
      // update target
      BTB_dest[index][i] = getBTBDest(target);
      // update LRU
      BTB_lru[index][i] = 0;
      return;
    }
  }
}

// regenerate branch address for test the correctness of the framework
uint64_t BaseBPU::regenerateTagAddr(uint64_t set, uint64_t tag) {
  return ((tag << (int)std::log2(buffer_sets)) | set) << offset_btb;
}

uint64_t BaseBPU::regenerateDestAddr(uint64_t dest) { return dest; }

int BaseBPU::checkPHTSetCollision(uint64_t addr1, uint64_t addr2) {
  return getPHTSet(addr1) == getPHTSet(addr2);
}
