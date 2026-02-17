import { generateText } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';

async function run() {
  const openai = createOpenAI({
    apiKey: process.env.OPENAI_API_KEY,
    baseURL: 'http://127.0.0.1:8787/v1',
    headers: {
      'x-sentinel-target': 'openai',
    },
  });

  const { text } = await generateText({
    model: openai('gpt-4.1-mini'),
    prompt: 'Explain why deterministic guardrails matter in three bullet points.',
  });

  console.log(text);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
