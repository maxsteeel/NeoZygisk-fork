import json
import os
import subprocess
import sys

release_zip = os.environ["RELEASE_ZIP_PATH"]
debug_zip = os.environ["DEBUG_ZIP_PATH"]

# Check that files exist before calling curl
if not os.path.exists(release_zip):
    sys.exit(f"ERROR: The file '{release_zip}' DOES NOT EXIST in this path.")
if not os.path.exists(debug_zip):
    sys.exit(f"ERROR: The file '{debug_zip}' DOES NOT EXIST in this path.")

# https://core.telegram.org/bots/api#markdownv2-style
token = os.environ["BOT_TOKEN"]
chat_id = os.environ["CHANNEL_ID"]
msg = os.environ["COMMIT_MESSAGE"].split('\n')[0].strip()
commit_url = os.environ["COMMIT_URL"]
run_url = os.environ["RUN_URL"]
run_number = os.environ["RUN_NUMBER"]
is_forced = os.environ.get("IS_FORCED", "false").lower() == "true"

MD_CHARS = '_*[]()~`>#+-=|{}.!'
ESCAPE_MD_MAP = {ord(c): f'\\{c}' for c in MD_CHARS}
ESCAPE_CODE_MAP = {ord('\\'): '\\\\', ord('`'): '\\`'}

title = "NeoZygisk-fork CI Build" + (" [FORCE PUSH BUILD]" if is_forced else "")
run_text = f"#ci_{run_number}"

escaped_title = title.translate(ESCAPE_MD_MAP)
escaped_run = run_text.translate(ESCAPE_MD_MAP)
escaped_msg = msg.translate(ESCAPE_CODE_MAP)

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
    "--form-string", f"media={json.dumps(media)}", 
    "-F", f"debug=@{debug_zip}",
    "-F", f"release=@{release_zip}"
]

print("Uploading artifacts to Telegram...")
result = subprocess.run(curl_cmd, capture_output=True, text=True)

# curl output validation
if result.returncode != 0:
    sys.exit(f"Critical error: curl failed locally (Exit code {result.returncode})\nError details: {result.stderr}")

# Telegram response validation
try:
    response = json.loads(result.stdout)
    if not response.get("ok"):
        sys.exit(f"Error returned by Telegram API:\n{json.dumps(response, indent=2)}")
    print("Artifacts successfully uploaded!")
except json.JSONDecodeError:
    sys.exit(f"Telegram response is not valid JSON:\n{result.stdout}")
