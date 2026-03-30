#!/bin/bash
set -e

SKILL_NAME="aws-waf-rules-reviewer"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$HOME/.kiro/skills/$SKILL_NAME"
AGENT_DIR="$HOME/.kiro/agents"
AGENT_FILE="$AGENT_DIR/$SKILL_NAME.json"

# Verify source files exist
for f in SKILL.md references/checklist.md references/waf-knowledge.md "$SKILL_NAME.json" scripts/waf-preprocess.py; do
    if [ ! -f "$SCRIPT_DIR/$f" ]; then
        echo "Error: $f not found in $SCRIPT_DIR" >&2
        exit 1
    fi
done

# Uninstall existing
if [ -d "$SKILL_DIR" ] || [ -f "$AGENT_FILE" ]; then
    echo "Found existing installation, removing..."
    rm -rf "$SKILL_DIR"
    rm -f "$AGENT_FILE"
    echo "Removed."
fi

# Install skill
mkdir -p "$SKILL_DIR"
cp "$SCRIPT_DIR/SKILL.md" "$SKILL_DIR/"
cp -r "$SCRIPT_DIR/references" "$SKILL_DIR/"
cp -r "$SCRIPT_DIR/scripts" "$SKILL_DIR/"

# Install agent config
mkdir -p "$AGENT_DIR"
cp "$SCRIPT_DIR/$SKILL_NAME.json" "$AGENT_FILE"

# Verify installation
for f in "$SKILL_DIR/SKILL.md" "$SKILL_DIR/references/checklist.md" "$SKILL_DIR/references/waf-knowledge.md" "$SKILL_DIR/scripts/waf-preprocess.py" "$AGENT_FILE"; do
    if [ ! -f "$f" ]; then
        echo "Error: installation verification failed — $f not found" >&2
        exit 1
    fi
done

echo "Installed skill to $SKILL_DIR"
echo "Installed agent config to $AGENT_FILE"
echo ""
echo "Done. Installation successful."
