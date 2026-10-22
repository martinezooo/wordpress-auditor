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

# The lab is explicitly local; this enables disposable Application Passwords
# for real role-boundary tests over loopback HTTP without weakening production.
WP config set WP_ENVIRONMENT_TYPE local

# Object-boundary fixtures are idempotent so an existing lab gains new cases.
if ! WP post list --post_type=post --name=scheduled-object-boundary \
        --format=count | grep -qE '^[1-9][0-9]*$'; then
  WP post create --post_title="Scheduled object boundary" \
     --post_name=scheduled-object-boundary --post_content="LAB-FUTURE-SECRET" \
     --post_status=future --post_date="2037-01-02 03:04:05"
fi
if ! WP post list --post_type=post --name=protected-object-boundary \
        --format=count | grep -qE '^[1-9][0-9]*$'; then
  WP post create --post_title="Protected object boundary" \
     --post_name=protected-object-boundary --post_content="LAB-PROTECTED-SECRET" \
     --post_status=publish --post_password="lab-only-post-pass"
fi
if ! WP post list --post_type=post --name=revision-object-boundary \
        --format=count | grep -qE '^[1-9][0-9]*$'; then
  revision_id="$(WP post create --porcelain --post_title="Revision object boundary" \
     --post_name=revision-object-boundary --post_content="LAB-REVISION-ONE" \
     --post_status=publish)"
  WP post update "$revision_id" --post_content="LAB-REVISION-TWO"
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
    # Plugins WITHOUT an ABSPATH guard: requested directly they crash with HTTP 500.
    # lab-crash hides the error; lab-leak shows PHP errors (display_errors on).
    for slug in lab-crash lab-leak; do
      leak="";  [ "$slug" = "lab-leak" ] && leak='ini_set("display_errors","1"); error_reporting(E_ALL);'
      docker compose exec -T wordpress sh -c "mkdir -p wp-content/plugins/$slug && \
        printf '<?php\n/* Plugin Name: $slug */\nif (!defined(\"ABSPATH\")) { $leak lab_undefined_function(); }\nadd_action(\"wp_enqueue_scripts\", function(){ wp_enqueue_style(\"$slug\", plugins_url(\"style.css\", __FILE__)); });\n' > wp-content/plugins/$slug/$slug.php && \
        echo 'body{}' > wp-content/plugins/$slug/style.css && chown -R www-data:www-data wp-content/plugins/$slug"
      WP plugin activate "$slug" || true
    done
    # Generic deployment mistake used to verify the context-triggered source
    # backup branch. It is not a plugin CVE and contains throwaway lab code.
    docker compose exec -T wordpress sh -c \
      'cp wp-content/plugins/lab-crash/lab-crash.php wp-content/plugins/lab-crash/lab-crash.php.bak; chown www-data:www-data wp-content/plugins/lab-crash/lab-crash.php.bak'
    ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
echo "Lab ready ($MODE): http://127.0.0.1:8088"
