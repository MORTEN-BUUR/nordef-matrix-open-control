from __future__ import annotations

from .models import SharedChannelObservation
from .policy import CODE_BLOCK, CODE_SAFE


def classify_channel(observation: SharedChannelObservation | None) -> tuple[int, str]:
    if observation is None:
        return CODE_SAFE, "no_shared_channel"
    writers = {x for x in observation.writable_by_agents if x}
    if len(writers) > 1:
        return CODE_BLOCK, "cross_agent_writable_channel"
    if writers and observation.agent_id not in writers:
        return CODE_BLOCK, "agent_not_channel_owner"
    return CODE_SAFE, "single_agent_namespace"
