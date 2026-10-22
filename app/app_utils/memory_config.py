# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shared Agent Platform Memory Bank configuration for Kubernetes investigations."""

from vertexai._genai.types import (
    ManagedTopicEnum,
)
from vertexai._genai.types import (
    MemoryBankCustomizationConfig as CustomizationConfig,
)
from vertexai._genai.types import (
    MemoryBankCustomizationConfigMemoryTopic as MemoryTopic,
)
from vertexai._genai.types import (
    MemoryBankCustomizationConfigMemoryTopicCustomMemoryTopic as CustomMemoryTopic,
)
from vertexai._genai.types import (
    MemoryBankCustomizationConfigMemoryTopicManagedMemoryTopic as ManagedMemoryTopic,
)
from vertexai._genai.types import (
    ReasoningEngineContextSpecMemoryBankConfig as MemoryBankConfig,
)

# Define which memory topics the Agent Platform Memory Bank extracts and persists
# across Kubernetes incident investigation sessions.
memory_bank_config = MemoryBankConfig(
    customization_configs=[
        CustomizationConfig(
            memory_topics=[
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.KEY_CONVERSATION_DETAILS,
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.EXPLICIT_INSTRUCTIONS,
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.USER_PREFERENCES,
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.USER_PERSONAL_INFO,
                    ),
                ),
                MemoryTopic(
                    custom_memory_topic=CustomMemoryTopic(
                        label="kubernetes_incident_findings",
                        description=(
                            "Extract root causes, failure categories (such as OOMKilled, "
                            "CrashLoopBackOff, ImagePullBackOff, probe failures, NodeNotReady, "
                            "MemoryPressure, DNS/network or RBAC issues), affected pod, "
                            "deployment, and node names, namespaces, container images, "
                            "exit codes, and key log/event evidence from Kubernetes "
                            "incident investigations."
                        ),
                    ),
                ),
                MemoryTopic(
                    custom_memory_topic=CustomMemoryTopic(
                        label="remediation_and_runbook_actions",
                        description=(
                            "Extract successful remediation steps, configuration changes, "
                            "resource limit adjustments, rollout rollbacks, and diagnostic "
                            "kubectl commands applied or recommended for past Kubernetes "
                            "incidents."
                        ),
                    ),
                ),
            ],
        ),
    ],
)
