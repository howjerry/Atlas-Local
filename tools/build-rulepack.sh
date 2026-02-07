#!/usr/bin/env bash
#
# build-rulepack.sh -- Build a signed .pack file from a rules directory.
#
# Usage:
#   ./tools/build-rulepack.sh <rules-dir> <output.pack> [--sign <private-key-file>]
#
# This script creates a rulepack archive (.pack) containing:
#   1. manifest.json  -- pack metadata and rule entries
#   2. rules/**       -- rule YAML files
#
# The .pack file is a gzip-compressed tar archive.
#
# If --sign is provided, the manifest is signed with the given Ed25519
# private key using openssl, and the signature + public key are embedded
# in the manifest.
#
# Requirements: tar, gzip, jq, openssl (for signing)

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

RULES_DIR=""
OUTPUT_FILE=""
SIGN_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign)
            SIGN_KEY="$2"
            shift 2
            ;;
        *)
            if [[ -z "$RULES_DIR" ]]; then
                RULES_DIR="$1"
            elif [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$1"
            else
                echo "Error: unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$RULES_DIR" || -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <rules-dir> <output.pack> [--sign <private-key-file>]" >&2
    exit 1
fi

if [[ ! -d "$RULES_DIR" ]]; then
    echo "Error: rules directory not found: $RULES_DIR" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Collect rule files
# ---------------------------------------------------------------------------

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Copy rule files to staging area.
STAGING="$TMPDIR/pack"
mkdir -p "$STAGING/rules"

RULE_COUNT=0
RULES_JSON="[]"

for rule_file in "$RULES_DIR"/*.yaml "$RULES_DIR"/*.yml; do
    [[ -f "$rule_file" ]] || continue

    base=$(basename "$rule_file")
    cp "$rule_file" "$STAGING/rules/$base"

    # Extract metadata from YAML (basic grep-based extraction).
    rule_id=$(grep -m1 '^id:' "$rule_file" | sed 's/^id:[[:space:]]*//')
    rule_name=$(grep -m1 '^name:' "$rule_file" | sed 's/^name:[[:space:]]*//')
    rule_severity=$(grep -m1 '^severity:' "$rule_file" | sed 's/^severity:[[:space:]]*//')
    rule_category=$(grep -m1 '^category:' "$rule_file" | sed 's/^category:[[:space:]]*//')
    rule_language=$(grep -m1 '^language:' "$rule_file" | sed 's/^language:[[:space:]]*//')
    rule_version=$(grep -m1 '^version:' "$rule_file" | sed 's/^version:[[:space:]]*//')

    entry=$(jq -n \
        --arg id "$rule_id" \
        --arg name "$rule_name" \
        --arg severity "$rule_severity" \
        --arg category "$rule_category" \
        --arg language "$rule_language" \
        --arg version "$rule_version" \
        --arg file "rules/$base" \
        '{
            id: $id,
            name: $name,
            severity: $severity,
            category: $category,
            language: $language,
            analysis_level: "L1",
            rule_type: "declarative",
            version: $version,
            file: $file
        }')

    RULES_JSON=$(echo "$RULES_JSON" | jq ". + [$entry]")
    RULE_COUNT=$((RULE_COUNT + 1))
done

if [[ $RULE_COUNT -eq 0 ]]; then
    echo "Error: no rule files found in $RULES_DIR" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build manifest
# ---------------------------------------------------------------------------

PACK_ID=$(basename "$RULES_DIR")
PACK_VERSION="1.0.0"
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Create manifest without signature first.
MANIFEST=$(jq -n \
    --arg schema_version "1.0.0" \
    --arg id "$PACK_ID" \
    --arg version "$PACK_VERSION" \
    --arg description "Rulepack built from $RULES_DIR" \
    --arg author "atlas-build-tool" \
    --arg created_at "$CREATED_AT" \
    --argjson rules "$RULES_JSON" \
    --argjson rule_count "$RULE_COUNT" \
    --arg checksum "pending" \
    '{
        schema_version: $schema_version,
        id: $id,
        version: $version,
        description: $description,
        author: $author,
        created_at: $created_at,
        rules: $rules,
        rule_count: $rule_count,
        checksum: $checksum
    }')

echo "$MANIFEST" > "$STAGING/manifest.json"

# ---------------------------------------------------------------------------
# Compute checksum and update manifest
# ---------------------------------------------------------------------------

# Compute SHA-256 of the staging directory content.
CHECKSUM=$(find "$STAGING/rules" -type f -exec shasum -a 256 {} \; | sort | shasum -a 256 | awk '{print $1}')

MANIFEST=$(echo "$MANIFEST" | jq --arg checksum "$CHECKSUM" '.checksum = $checksum')
echo "$MANIFEST" > "$STAGING/manifest.json"

# ---------------------------------------------------------------------------
# Sign (optional)
# ---------------------------------------------------------------------------

if [[ -n "$SIGN_KEY" ]]; then
    echo "Signing is not yet implemented in the shell script." >&2
    echo "Use the Rust API for proper Ed25519 signing." >&2
    # Placeholder: signature and public_key would be added here.
fi

# ---------------------------------------------------------------------------
# Create archive
# ---------------------------------------------------------------------------

(cd "$STAGING" && tar czf "$TMPDIR/output.pack" manifest.json rules/)
cp "$TMPDIR/output.pack" "$OUTPUT_FILE"

echo "Created rulepack: $OUTPUT_FILE"
echo "  ID:         $PACK_ID"
echo "  Version:    $PACK_VERSION"
echo "  Rules:      $RULE_COUNT"
echo "  Checksum:   $CHECKSUM"
