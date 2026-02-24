module ThreatIntelMesh

sig Node {}

one sig LocalNode extends Node {}

sig Snapshot {
  owner: one Node,
  signed: one Bool,
  signatures: set Signature
}

sig Signature {}

sig Policy {
  allowUnsignedImport: one Bool
}

pred canImport[p: Policy, s: Snapshot] {
  (p.allowUnsignedImport = True) or (s.signed = True)
}

assert UnsignedImportMustBeDenied {
  all p: Policy, s: Snapshot |
    p.allowUnsignedImport = False and s.signed = False implies not canImport[p, s]
}

assert SignedImportMayBeAccepted {
  all p: Policy, s: Snapshot |
    s.signed = True implies canImport[p, s]
}

check UnsignedImportMustBeDenied for 5
check SignedImportMayBeAccepted for 5
