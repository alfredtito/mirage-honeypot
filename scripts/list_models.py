"""List models available to your Token Factory key. Run this first to confirm model IDs.

    python scripts/list_models.py            # everything
    python scripts/list_models.py nemotron   # filter by substring
"""
import os
import sys

from openai import OpenAI

client = OpenAI(
    api_key=os.environ["NEBIUS_API_KEY"],
    base_url=os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/"),
)
needle = sys.argv[1].lower() if len(sys.argv) > 1 else ""
for m in sorted(client.models.list().data, key=lambda m: m.id):
    if needle in m.id.lower():
        print(m.id)
