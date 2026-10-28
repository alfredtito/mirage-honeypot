import os, sys, time
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["NEBIUS_API_KEY"],
    base_url=os.environ.get("NEBIUS_BASE_URL", "https://integrate.api.nvidia.com/v1"),
    timeout=30,
    max_retries=0,
)
needle = sys.argv[1].lower() if len(sys.argv) > 1 else "nemotron"
ids = sorted(m.id for m in client.models.list().data if needle in m.id.lower())
print(f"testing {len(ids)} models\n")
for mid in ids:
    t0 = time.perf_counter()
    try:
        r = client.chat.completions.create(
            model=mid,
            messages=[{"role": "user", "content": "Reply with the single word: ready"}],
            max_tokens=20,
        )
        ms = int((time.perf_counter() - t0) * 1000)
        text = (r.choices[0].message.content or "").strip().replace("\n", " ")[:40]
        print(f"OK    {ms:>6} ms  {mid}  -> {text!r}")
    except Exception as e:
        print(f"FAIL  {type(e).__name__:<18} {mid}")
