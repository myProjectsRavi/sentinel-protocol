import { ChatOpenAI } from '@langchain/openai';

async function run() {
  const model = new ChatOpenAI({
    model: 'gpt-4.1-mini',
    temperature: 0,
    apiKey: process.env.OPENAI_API_KEY,
    configuration: {
      baseURL: 'http://127.0.0.1:8787/v1',
      defaultHeaders: {
        'x-sentinel-target': 'openai',
      },
    },
  });

  const response = await model.invoke('Summarize this request in one sentence.');
  console.log(response.content);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
