#!/usr/bin/env bash
# Idempotent rig setup for task-4's live --send-recovery-email verification.
#
# authentik ships with no recovery flow and no email stage out of the box
# (confirmed against a fresh 2024.10.5 bootstrap) -- unlike Keycloak's realm
# import (task-0), there is no declarative "import this flow" mechanism, so
# this script is the equivalent: it creates a recovery flow, an email stage
# pointed at the compose file's global SMTP settings (mailpit), binds the
# stage into the flow, and assigns the flow to the default brand. Safe to
# re-run -- every step checks for the object by name/slug first.
#
# Usage: AK_URL=http://localhost:9000 AK_TOKEN=... deploy/authentik/setup-recovery.sh
# Prints the email stage UUID on success, for use as --email-stage.

set -euo pipefail

AK_URL="${AK_URL:-http://localhost:9000}"
AK_TOKEN="${AK_TOKEN:?AK_TOKEN must be set}"
FLOW_SLUG="kc2ak-recovery"
STAGE_NAME="kc2ak-email"

_curl() {
  curl -sS -H "Authorization: Bearer $AK_TOKEN" -H "Content-Type: application/json" "$@"
}

flow_pk=$(_curl "$AK_URL/api/v3/flows/instances/?slug=$FLOW_SLUG" \
  | python3 -c "import json,sys; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
if [ -z "$flow_pk" ]; then
  flow_pk=$(_curl -X POST "$AK_URL/api/v3/flows/instances/" \
    -d "{\"name\":\"$FLOW_SLUG\",\"slug\":\"$FLOW_SLUG\",\"title\":\"kc2ak recovery\",\"designation\":\"recovery\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['pk'])")
  echo "created flow $flow_pk" >&2
fi

stage_pk=$(_curl "$AK_URL/api/v3/stages/email/?name=$STAGE_NAME" \
  | python3 -c "import json,sys; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
if [ -z "$stage_pk" ]; then
  stage_pk=$(_curl -X POST "$AK_URL/api/v3/stages/email/" \
    -d "{\"name\":\"$STAGE_NAME\",\"use_global_settings\":true}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['pk'])")
  echo "created email stage $stage_pk" >&2
fi

already_bound=$(_curl "$AK_URL/api/v3/flows/bindings/?target=$flow_pk&stage=$stage_pk" \
  | python3 -c "import json,sys; print(bool(json.load(sys.stdin)['results']))")
if [ "$already_bound" != "True" ]; then
  _curl -X POST "$AK_URL/api/v3/flows/bindings/" \
    -d "{\"target\":\"$flow_pk\",\"stage\":\"$stage_pk\",\"order\":10}" >/dev/null
  echo "bound stage to flow" >&2
fi

brand=$(_curl "$AK_URL/api/v3/core/brands/" \
  | python3 -c "import json,sys; r=json.load(sys.stdin)['results']; b=next((x for x in r if x['default']), r[0] if r else None); print(json.dumps(b) if b else '')")
brand_uuid=$(echo "$brand" | python3 -c "import json,sys; s=sys.stdin.read(); print(json.loads(s)['brand_uuid'] if s else '')")
current_recovery=$(echo "$brand" | python3 -c "import json,sys; s=sys.stdin.read(); print(json.loads(s).get('flow_recovery') or '' if s else '')")
if [ "$current_recovery" != "$flow_pk" ]; then
  _curl -X PATCH "$AK_URL/api/v3/core/brands/$brand_uuid/" -d "{\"flow_recovery\":\"$flow_pk\"}" >/dev/null
  echo "set brand flow_recovery" >&2
fi

echo "$stage_pk"
