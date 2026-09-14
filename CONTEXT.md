# Audit side effects

Notification and forwarding work requested by matching audit rule groups.

## Language

**Side-effect task**:
The notification and/or forwarding work requested for one audit frame by one matching rule group.

**Delivery attempt**:
A reserved opportunity to perform a side-effect task's notification and/or forwarding, counted against its allowance even if interrupted before sending. Retrying a dead-letter handoff is not a delivery attempt.

**Delivery limit**:
The maximum number of delivery attempts allowed for a side-effect task, fixed when the task is accepted. Later configuration changes do not alter that task's limit.

**Exhausted task**:
A side-effect task whose final permitted delivery attempt failed or was interrupted. It is no longer eligible for another delivery attempt, including during recovery, and awaits completion of its dead-letter handoff.

**Dead-letter task**:
An exhausted task retained for inspection with a reason for stopping delivery.
