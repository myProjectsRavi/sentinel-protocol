# syntax=docker/dockerfile:1.7

FROM node:20-bookworm-slim AS build

WORKDIR /app

# onnxruntime-node may require native build tooling on some platforms.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY cli ./cli
COPY src ./src
COPY scripts/preload-models.js ./scripts/preload-models.js
COPY README.md LICENSE ./

FROM node:20-bookworm-slim AS runtime

ARG PRELOAD_SEMANTIC_MODEL=true
ARG PRELOAD_MODEL_ID=Xenova/bert-base-NER
ARG PRELOAD_NEURAL_MODEL=true
ARG PRELOAD_NEURAL_MODEL_ID=Xenova/all-MiniLM-L6-v2

ENV NODE_ENV=production \
    HOME=/home/sentinel \
    SENTINEL_HOME=/var/lib/sentinel \
    SENTINEL_PORT=8787 \
    SENTINEL_AUDIT_STDOUT=true

WORKDIR /app

RUN groupadd --system sentinel \
  && useradd --system --gid sentinel --create-home --home-dir /home/sentinel sentinel \
  && mkdir -p /etc/sentinel "$SENTINEL_HOME" \
  && chown -R sentinel:sentinel /etc/sentinel "$SENTINEL_HOME"

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/cli ./cli
COPY --from=build /app/src ./src
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/README.md ./README.md
COPY --from=build /app/LICENSE ./LICENSE

RUN cp ./src/config/default.yaml /etc/sentinel/sentinel.yaml \
  && chown sentinel:sentinel /etc/sentinel/sentinel.yaml

USER sentinel

# Default warmup: downloads semantic/neural models at build time to avoid first-request latency spikes.
RUN if [ "$PRELOAD_SEMANTIC_MODEL" = "true" ]; then \
      node ./cli/sentinel.js models download --model-id "$PRELOAD_MODEL_ID" --cache-dir /home/sentinel/.sentinel/models ; \
    else \
      echo "Skipping semantic model preload (PRELOAD_SEMANTIC_MODEL=false)"; \
    fi \
  && if [ "$PRELOAD_NEURAL_MODEL" = "true" ]; then \
      node ./scripts/preload-models.js --model-id "$PRELOAD_NEURAL_MODEL_ID" --cache-dir /home/sentinel/.sentinel/models ; \
    else \
      echo "Skipping neural model preload (PRELOAD_NEURAL_MODEL=false)"; \
    fi

EXPOSE 8787

ENTRYPOINT ["node", "./cli/sentinel.js"]
CMD ["start", "--config", "/etc/sentinel/sentinel.yaml", "--host", "0.0.0.0", "--port", "8787"]
