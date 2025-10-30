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
# date: 2024/12/30
# =============================================================================
FROM ubuntu:22.04
LABEL authors="iamywang"

# set the working directory
WORKDIR /branch-gauge
COPY ./ .

# install dependencies
RUN DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y tzdata
RUN apt-get install -y build-essential cmake gcc g++ python3 python3-pip python3-matplotlib python3-numpy

# compile the project
RUN mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j

# set the entrypoint
CMD ["/bin/bash"]

# Then, you can run the following command to build and run the container:
# docker build -t branchgauge .
# docker run -it branchgauge