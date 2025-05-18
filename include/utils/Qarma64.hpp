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
// date: 2024/11/21
// =============================================================================
// This file is modified from Phantom1003/QARMA64
// Repo: https://github.com/Phantom1003/QARMA64
// =============================================================================
#ifndef QARMA64_HPP
#define QARMA64_HPP
class QARMA {
#define MAX_LENGTH 64
#define subcells sbox[sbox_use]
#define subcells_inv sbox_inv[sbox_use]

  typedef unsigned long long int const_t;
  typedef unsigned long long int tweak_t;
  typedef unsigned long long int text_t;
  typedef unsigned long long int key_t;
  typedef unsigned char cell_t;

  // int sbox_use = 0;
  // text_t check_box[3] = { 0x3ee99a6c82af0c38, 0x9f5c41ec525603c9,
  // 0xbcaf6c89de930765 };

  // int sbox_use = 1;
  // text_t check_box[3] = { 0x544b0ab95bda7c3a, 0xa512dd1e4e3ec582,
  // 0xedf67ff370a483f2 };

  int sbox_use = 2;
  text_t check_box[3] = {0xc003b93999b33765, 0x270a787275c48d10,
                         0x5c06a7501b63b2fd};

  int m = 4;

  const_t alpha = 0xC0AC29B7C97C50DD;
  const_t c[8] = {0x0000000000000000, 0x13198A2E03707344, 0xA4093822299F31D0,
                  0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C,
                  0x3F84D5B5B5470917, 0x9216D5D98979FB1B};

  int sbox[3][16] = {{0, 14, 2, 10, 9, 15, 8, 11, 6, 4, 3, 7, 13, 12, 1, 5},
                     {10, 13, 14, 6, 15, 7, 3, 5, 9, 8, 0, 12, 11, 1, 2, 4},
                     {11, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10}};

  int sbox_inv[3][16] = {
      {0, 14, 2, 10, 9, 15, 8, 11, 6, 4, 3, 7, 13, 12, 1, 5},
      {10, 13, 14, 6, 15, 7, 3, 5, 9, 8, 0, 12, 11, 1, 2, 4},
      {5, 14, 13, 8, 10, 11, 1, 9, 2, 6, 15, 0, 4, 12, 7, 3}};

  int t[16] = {0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2};
  int t_inv[16] = {0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12};
  int h[16] = {6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11};
  int h_inv[16] = {4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3};

#define Q M
#define M_inv M
  cell_t M[16] = {0, 1, 2, 1, 1, 0, 1, 2, 2, 1, 0, 1, 1, 2, 1, 0};

public:
  void text2cell(cell_t *cell, text_t is);

  text_t cell2text(cell_t *cell);

  text_t pseudo_reflect(text_t is, key_t tk);

  text_t forward(text_t is, key_t tk, int r);

  text_t backward(text_t is, key_t tk, int r);

  cell_t LFSR(cell_t x);

  cell_t LFSR_inv(cell_t x);

  key_t forward_update_key(key_t T);

  key_t backward_update_key(key_t T);

  text_t qarma64_enc(text_t plaintext, tweak_t tweak, key_t w0, key_t k0,
                     int rounds);

  text_t qarma64_dec(text_t plaintext, tweak_t tweak, key_t w0, key_t k0,
                     int rounds);
};
#endif
