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

# author: iamywang
# date: 2025/01/11
# =============================================================================
#!/bin/bash
python3 fig6-reuse-n.py
python3 fig7-reuse-pr.py
python3 fig8-btb-prune-n.py
python3 fig9-btb-prune-pr.py
python3 fig10-pht-occupancy-n.py
python3 fig11-btb-occupancy-n.py
python3 fig12-pht-occupancy-pr.py
python3 fig13-btb-occupancy-pr.py
python3 fig14-leakage-reuse-1.py
python3 fig15-leakage-reuse-2.py
python3 tab2-leakage-pht.py
python3 tab3-leakage-btb.py