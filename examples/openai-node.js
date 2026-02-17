const payload = {
  model: 'gpt-4.1-mini',
  messages: [{ role: 'user', content: 'Hello from Sentinel' }],
};

async function main() {
  const response = await fetch('http://127.0.0.1:8787/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'x-sentinel-target': 'openai',
    },
    body: JSON.stringify(payload),
  });

  console.log('Status:', response.status);
  console.log('Body:', await response.text());
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
