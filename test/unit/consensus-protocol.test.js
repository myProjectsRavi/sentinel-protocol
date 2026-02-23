const { ConsensusProtocol } = require('../../src/security/consensus-protocol');

describe('ConsensusProtocol', () => {
  test('blocks high-risk action when quorum is not met', () => {
    const protocol = new ConsensusProtocol({
      enabled: true,
      mode: 'block',
      block_on_no_quorum: true,
      required_votes: 2,
      total_agents: 3,
      high_risk_actions: ['wire_funds'],
    });

    const decision = protocol.evaluate({
      bodyJson: {
        action: 'wire_funds',
        agent_votes: [{ agent_id: 'a1', decision: 'approve' }],
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.reason).toBe('consensus_quorum_not_met');
  });

  test('returns clean for non high-risk action', () => {
    const protocol = new ConsensusProtocol({ enabled: true, high_risk_actions: ['wire_funds'] });
    const decision = protocol.evaluate({ bodyJson: { action: 'read_docs' } });
    expect(decision.detected).toBe(false);
  });
});
