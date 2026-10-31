import os
from dotenv import load_dotenv

# Load local environment variables if available
load_dotenv(os.path.join(os.path.dirname(__file__), "backend", ".env"))
load_dotenv()

from anthropic import Anthropic, APIError

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")
MAX_TOKENS = 1200


def main():
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Set ANTHROPIC_API_KEY in your terminal or backend/.env, then run again.")
        return

    if MODEL == "YOUR_APPROVED_MODEL_ID":
        print("Set ANTHROPIC_MODEL to the model ID supplied by the organizers.")
        return

    client = Anthropic(api_key=api_key)
    messages = []
    print(f"Claude Hackathon Starter | Model: {MODEL}")
    print("Type a message. Use /clear to reset history or /exit to quit.\n")

    while True:
        try:
            prompt = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not prompt:
            continue

        if prompt.lower() in {"/exit", "/quit"}:
            break

        if prompt.lower() == "/clear":
            messages.clear()
            print("Conversation history cleared.\n")
            continue

        messages.append({"role": "user", "content": prompt})

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system="You are a helpful hackathon development assistant. Give clear, practical answers.",
                messages=messages,
            )

            answer = "\n".join(
                block.text for block in response.content
                if getattr(block, "type", None) == "text"
            ).strip()

            if answer:
                print(f"\nClaude: {answer}\n")
                messages.append({"role": "assistant", "content": answer})
            else:
                print("Claude returned no text response. Check model configuration.")

            if response.stop_reason == "max_tokens":
                print(f"(Reached the {MAX_TOKENS}-token output limit.)")

        except APIError as exc:
            print(f"API request failed: {exc.__class__.__name__}: {exc}")
            if messages and messages[-1].get("role") == "user":
                messages.pop()


if __name__ == "__main__":
    main()

