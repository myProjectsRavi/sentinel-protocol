---- MODULE InjectionGuard ----
EXTENDS Reals

VARIABLES score, blockThreshold, mode, effectiveMode, shouldBlock

Init ==
  /\ score = 0.0
  /\ blockThreshold = 0.8
  /\ mode = "monitor"
  /\ effectiveMode = "monitor"
  /\ shouldBlock = FALSE

ObserveLowRisk ==
  /\ score' \in {0.0, 0.2, 0.4}
  /\ UNCHANGED blockThreshold
  /\ UNCHANGED mode
  /\ UNCHANGED effectiveMode
  /\ shouldBlock' = FALSE

ObserveHighRiskMonitor ==
  /\ score' \in {0.8, 0.9, 1.0}
  /\ mode' = "block"
  /\ effectiveMode' = "monitor"
  /\ UNCHANGED blockThreshold
  /\ shouldBlock' = FALSE

ObserveHighRiskEnforce ==
  /\ score' \in {0.8, 0.9, 1.0}
  /\ mode' = "block"
  /\ effectiveMode' = "enforce"
  /\ UNCHANGED blockThreshold
  /\ shouldBlock' = TRUE

Next == ObserveLowRisk \/ ObserveHighRiskMonitor \/ ObserveHighRiskEnforce

Spec == Init /\ [][Next]_<<score, blockThreshold, mode, effectiveMode, shouldBlock>>

EnforceBlocksHighRisk == (mode = "block" /\ effectiveMode = "enforce" /\ score >= blockThreshold) => shouldBlock
MonitorNeverBlocks == effectiveMode = "monitor" => ~shouldBlock

====
