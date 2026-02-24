---- MODULE SerializationFirewall ----
EXTENDS Naturals

CONSTANT MaxDepth

VARIABLES depth, gadgetDetected, allowlistedFormat, decision

Init ==
  /\ depth = 0
  /\ gadgetDetected = FALSE
  /\ allowlistedFormat = TRUE
  /\ decision = "allow"

ParseSafe ==
  /\ depth' \in 0..MaxDepth
  /\ gadgetDetected' = FALSE
  /\ allowlistedFormat' = TRUE
  /\ decision' = "allow"

DepthBomb ==
  /\ depth' \in (MaxDepth + 1)..(MaxDepth + 5)
  /\ UNCHANGED gadgetDetected
  /\ UNCHANGED allowlistedFormat
  /\ decision' = "block"

GadgetPayload ==
  /\ gadgetDetected' = TRUE
  /\ depth' \in 0..(MaxDepth + 5)
  /\ UNCHANGED allowlistedFormat
  /\ decision' = "block"

UnknownFormat ==
  /\ allowlistedFormat' = FALSE
  /\ depth' \in 0..(MaxDepth + 5)
  /\ UNCHANGED gadgetDetected
  /\ decision' = "block"

Next == ParseSafe \/ DepthBomb \/ GadgetPayload \/ UnknownFormat

Spec == Init /\ [][Next]_<<depth, gadgetDetected, allowlistedFormat, decision>>

NoExploitAllowed == gadgetDetected => decision = "block"
DepthBombBlocked == depth > MaxDepth => decision = "block"
UnknownFormatBlocked == ~allowlistedFormat => decision = "block"

====
