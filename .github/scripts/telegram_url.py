import json
import os
import subprocess
import sys

release_zip = os.environ["RELEASE_ZIP_PATH"]
debug_zip = os.environ["DEBUG_ZIP_PATH"]

# Check that files exist before calling curl
if not os.path.exists(release_zip):
    print(f"ERROR: The file '{release_zip}' DOES NOT EXIST in this path.")
    sys.exit(1)
if not os.path.exists(debug_zip):
    print(f"ERROR: The file '{debug_zip}' DOES NOT EXIST in this path.")
    sys.exit(1)

# https://core.telegram.org/bots/api#markdownv2-style
token = os.environ["BOT_TOKEN"]
chat_id = os.environ["CHANNEL_ID"]
full_msg = os.environ["COMMIT_MESSAGE"]
msg = full_msg.split('\n')[0].strip()
commit_url = os.environ["COMMIT_URL"]
run_url = os.environ["RUN_URL"]
run_number = os.environ["RUN_NUMBER"]
is_forced = os.environ.get("IS_FORCED", "false").lower() == "true"

def escape_md(text):
    for c in ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']:
        text = text.replace(c, f'\\{c}')
    return text

def escape_code(text):
    text = text.replace('\\', '\\\\')
    text = text.replace('`', '\\`')
    return text

title = "NeoZygisk-fork CI Build"

if is_forced:
    title += " [FORCE PUSH BUILD]"

run_text = f"#ci_{run_number}"

escaped_title = escape_md(title)
escaped_run = escape_md(run_text)
escaped_msg = escape_code(msg)

caption = f"*{escaped_title}*\n{escaped_run}\n\n```\n{escaped_msg}\n```\n[Commit]({commit_url})\n[Workflow run]({run_url})"

if len(caption) > 1024:
    caption = caption[:1015] + "...\n```"

media = [
    {"type": "document", "media": "attach://debug"},
    {"type": "document", "media": "attach://release", "caption": caption, "parse_mode": "MarkdownV2"}
]

# curl with -sS (Silent + Show error)
url_telegram = "https://api.telegram" + f".org/bot{token}/sendMediaGroup"

curl_cmd = [
    "curl", "-sS", "-X", "POST",
    url_telegram,
    "-F", f"chat_id={chat_id}",
    "-F", f"media={json.dumps(media)}",
    "-F", f"debug=@{debug_zip}",
    "-F", f"release=@{release_zip}"
]

print("Uploading artifacts to Telegram...")
result = subprocess.run(curl_cmd, capture_output=True, text=True)

# curl output validation
if result.returncode != 0:
    print(f"Critical error: curl failed locally (Exit code {result.returncode})")
    print("Error details:", result.stderr)
    sys.exit(1)

# Telegram response validation
try:
    response = json.loads(result.stdout)
    if not response.get("ok"):
        print("Error returned by Telegram API:")
        print(json.dumps(response, indent=2))
        sys.exit(1)
    else:
        print("Artifacts successfully uploaded!")
except json.JSONDecodeError:
    print("Telegram response is not valid JSON:")
    print(result.stdout)
    sys.exit(1)
