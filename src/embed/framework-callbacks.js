function buildLifecycleEvent(name, payload = {}) {
  return {
    event: String(name || ''),
    timestamp: new Date().toISOString(),
    payload: payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {},
  };
}

function createFrameworkCallbacks(server, options = {}) {
  const sink = typeof options.onEvent === 'function' ? options.onEvent : null;

  function emit(name, payload) {
    const event = buildLifecycleEvent(name, payload);
    if (sink) {
      sink(event);
    }
    if (server?.agentObservability?.isEnabled?.()) {
      const context = server.agentObservability.startRequest({
        headers: payload?.headers || {},
        correlationId: payload?.correlation_id || payload?.correlationId || null,
        method: 'CALLBACK',
        path: '/embed/framework',
        requestStart: Date.now(),
      });
      if (context) {
        server.agentObservability.emitLifecycle(context, name, payload);
        server.agentObservability.finishRequest(context, {
          statusCode: 200,
          decision: 'callback_observed',
          provider: String(payload?.framework || 'embed'),
        });
      }
    }
    return event;
  }

  return {
    langchainCallback() {
      return {
        async handleLLMStart(llm, prompts = [], runId) {
          emit('agent.start', {
            framework: 'langchain',
            run_id: runId || null,
            prompt_count: Array.isArray(prompts) ? prompts.length : 0,
            model: llm?.modelName || llm?.model || null,
          });
        },
        async handleLLMEnd(output, runId) {
          emit('agent.complete', {
            framework: 'langchain',
            run_id: runId || null,
            generations: Array.isArray(output?.generations) ? output.generations.length : 0,
          });
        },
        async handleLLMError(error, runId) {
          emit('agent.error', {
            framework: 'langchain',
            run_id: runId || null,
            error: String(error?.message || error || 'unknown_error'),
          });
        },
      };
    },
    llamaIndexCallback() {
      return {
        async onStart(meta = {}) {
          emit('agent.start', {
            framework: 'llamaindex',
            run_id: meta.runId || null,
          });
        },
        async onComplete(meta = {}) {
          emit('agent.complete', {
            framework: 'llamaindex',
            run_id: meta.runId || null,
          });
        },
        async onError(error, meta = {}) {
          emit('agent.error', {
            framework: 'llamaindex',
            run_id: meta.runId || null,
            error: String(error?.message || error || 'unknown_error'),
          });
        },
      };
    },
    crewaiCallback() {
      return {
        async onTaskStart(task = {}, runId) {
          emit('agent.start', {
            framework: 'crewai',
            run_id: runId || task.runId || null,
            task: String(task.description || task.task || '').slice(0, 1024),
          });
        },
        async onTaskComplete(result = {}, runId) {
          emit('agent.complete', {
            framework: 'crewai',
            run_id: runId || result.runId || null,
            result_preview: String(result.output || result.result || '').slice(0, 1024),
          });
        },
        async onTaskError(error, runId) {
          emit('agent.error', {
            framework: 'crewai',
            run_id: runId || null,
            error: String(error?.message || error || 'unknown_error'),
          });
        },
      };
    },
  };
}

module.exports = {
  createFrameworkCallbacks,
};
