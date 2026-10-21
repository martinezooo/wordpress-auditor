#!/usr/bin/env bash
# Provision the local lab: roles, content in several statuses, misconfig toggles.
# Usage: bash lab/setup.sh [baseline|misconfigured]
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-baseline}"
WP() { docker compose run --rm -T wpcli wp "$@"; }

docker compose up -d
until curl -fsS -o /dev/null http://127.0.0.1:8088/wp-login.php 2>/dev/null \
   || curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/ | grep -qE '^(200|302)$'; do sleep 3; done

if ! WP core is-installed 2>/dev/null; then
  WP core install --url=http://127.0.0.1:8088 --title="Audit Lab" \
     --admin_user=labadmin --admin_password=lab-admin-pass --admin_email=admin@lab.invalid --skip-email
  for role in editor author contributor subscriber; do
    WP user create "lab$role" "lab$role@lab.invalid" --role="$role" --user_pass="lab-$role-pass"
  done
  WP rewrite structure '/%postname%/' --hard
  WP post create --post_title="Public post" --post_content="public body" --post_status=publish
  WP post create --post_title="Draft post" --post_content="LAB-DRAFT-SECRET" --post_status=draft
  WP post create --post_title="Private post" --post_content="LAB-PRIVATE-SECRET" --post_status=private
  WP post create --post_title="Pending post" --post_content="LAB-PENDING-SECRET" --post_status=pending
fi

case "$MODE" in
  baseline)
    WP option update users_can_register 0
    WP option update default_role subscriber
    ;;
  misconfigured)
    WP option update users_can_register 1
    WP option update default_role subscriber
    docker compose exec -T wordpress sh -c \
      'cp wp-config.php wp-config.php.bak; printf "WordPress database error lab\nPHP Warning: lab\n" > wp-content/debug.log; chown www-data:www-data wp-content/debug.log'
    ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
echo "Lab ready ($MODE): http://127.0.0.1:8088"
