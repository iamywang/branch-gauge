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
// date: 2024/12/15
// =============================================================================
#ifndef UTILS_HPP
#define UTILS_HPP
// replacement policy
#include <cstdint>
enum ReplacementPolicy { REPL_LRU = 0, REPL_RANDOM = 1 };

// security domain
enum SecurityDomain { DOM_ATTACKER = 0, DOM_VICTIM = 1 };

// BPU type
enum BPUType {
  BPU_BaseBPU = 0,
  BPU_BSUP = 1,
  BPU_XorBP = 2,
  BPU_NoisyXorBP = 3,
  BPU_LSBP = 4,
  BPU_STBPU = 5,
  BPU_HyBP = 6
};

// Encryption Keys
enum EncryptionKey {
  KEY_0 = 0x06FADE60,
  KEY_1 = 0xCAB4BEEF,
  KEY_2 = 0xCAFEEFAC,
  KEY_3 = 0x47110815,
  KEY_4 = 0x10FADE01,
  KEY_5 = 0xFE0123ED,
  KEY_6 = 0x04866840,
  KEY_7 = 0x80866808
};

// Processor PIDs
enum ProcessorPID { PID_ATTACKER = 0x1234, PID_VICTIM = 0x5678 };

// Maximum number of branches
extern uint64_t NUMBER_MAX_BRANCHES;
#endif