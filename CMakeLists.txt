# Copyright 2025 iamywang

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# BranchGauge: Modeling and Quantifying Leakage in Randomization-Based Secure
# Branch Predictors
#
# author: iamywang
# date: 2024/11/27
# =============================================================================
cmake_minimum_required(VERSION 3.10)

project(branch-gauge VERSION 1.0 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_SOURCES
    # utils
    include/utils/Qarma64.cpp
    # predictors
    predictors/BaseBPU.cpp
    predictors/BSUP.cpp
    predictors/XorBP.cpp
    predictors/NoisyXorBP.cpp
    predictors/LSBP.cpp
    predictors/STBPU.cpp
    predictors/HyBP.cpp
    # attacks
    attacks/BaseBPU.cpp
    attacks/BSUP.cpp
    attacks/XorBP.cpp
    attacks/NoisyXorBP.cpp
    attacks/LSBP.cpp
    attacks/STBPU.cpp
    attacks/HyBP.cpp
    # main
    main.cpp)

# dump the branch collision state during the attack
# add_definitions(-DDEBUG)

# dump the branch predictor state during the attack
# add_definitions(-DATTACK)

# dump the branch predictor state during the evaluation
add_definitions(-DEVALUATION)

# whether the key is random or fixed
add_definitions(-DRANDOM_KEY)

# whether the pid is random or fixed
add_definitions(-DRANDOM_PID)

# whether the max number of branch access is set to 1e9
add_definitions(-DLIMITED_BRANCH_ACCESS)

add_executable(branch-gauge ${PROJECT_SOURCES})

target_link_libraries(branch-gauge)
