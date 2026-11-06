#!/bin/bash
set +x
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
MANAGER_BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$MANAGER_BASE/scripts/common.sh"

atomic_file() {
    local source=$1 destination=$2 mode=$3 group=${4:-0} temp
    [[ ! -L $destination ]] || { error "Refusing symbolic link: $destination"; return 1; }
    temp=$(mktemp "${destination%/*}/.imunify-discord.XXXXXX") || return 1
    if cp -- "$source" "$temp" && chown "0:$group" "$temp" && chmod "$mode" "$temp" && mv -f -- "$temp" "$destination"; then return 0; fi
    rm -f -- "$temp"; return 1
}

manager_exit() {
    local rc=$1 failed=false
    trap - EXIT HUP INT TERM
    if [[ $rc != 0 && ${COMMITTED:-false} == false && -n ${BACKUP:-} ]]; then
        set +e
        printf 'Error: operation failed during %s (status %s); restoring previous state.\n' "$STAGE" "$rc" >&2
        if [[ ${NOTIFY_TOUCHED:-false} == true ]]; then notification_apply "$OLD_TARGETS" || failed=true; fi
        if [[ ${FILES_TOUCHED:-false} == true ]]; then
            rm -rf -- "$CONFIG" || failed=true
            if [[ -d $BACKUP/config ]]; then cp -a -- "$BACKUP/config" "$CONFIG" || failed=true; fi
            if [[ -f $BACKUP/cron ]]; then cp -a -- "$BACKUP/cron" "$CRON" || failed=true
            else rm -f -- "$CRON" || failed=true; fi
        fi
        if [[ ${ROOT_CRON_TOUCHED:-false} == true ]]; then crontab "$BACKUP/root-crontab" || failed=true; fi
        if [[ ${LEGACY_TOUCHED:-false} == true ]]; then cp -a -- "$BACKUP/legacy-cron" "$MIGRATE_CRON" || failed=true; fi
        if [[ $failed == true ]]; then printf 'Error: rollback incomplete. Protected backup: %s\n' "$BACKUP" >&2; BACKUP=; fi
    fi
    [[ -z ${BACKUP:-} ]] || rm -rf -- "$BACKUP"
    exit "$rc"
}

# Recognize only the documented equivalent legacy command. Never evaluate cron.
filter_cron() {
    local file=$1 system=$2 line minute hour day month weekday user rest expected found=0 schedule
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^[[:space:]]*(#|$) || $line != *imunify-antivirus* || $line != *on-demand* ]]; then printf '%s\n' "$line"; continue; fi
        if [[ $system == true ]]; then
            read -r minute hour day month weekday user rest <<< "$line"
            schedule="$minute $hour $day $month $weekday"
            [[ $user == root && $schedule == "$SCAN_CRON" ]] || { error 'Legacy scan schedule/user differs; migration stopped.'; return 1; }
            if [[ $rest =~ ^/usr/bin/flock\ -n\ /(var/run|run)/[A-Za-z0-9_.-]+\ (.*)$ ]]; then rest=${BASH_REMATCH[2]}; fi
            if [[ $rest =~ ^(.*)\ \>\>\ /var/log/[A-Za-z0-9_.-]+\ 2\>\&1$ ]]; then rest=${BASH_REMATCH[1]}; fi
        else read -r minute hour day month weekday rest <<< "$line"; fi
        rest=${rest%' >/dev/null 2>&1'}; rest=${rest%' > /dev/null 2>&1'}
        if [[ $system == true ]]; then
            expected="malware on-demand start --path $SCAN_PATH --no-follow-symlinks --intensity-cpu $SCAN_CPU --intensity-io $SCAN_IO"
            [[ $rest == "$AGENT $expected" || $rest == "/usr/bin/imunify-antivirus $expected" ]] || { error 'Unsupported legacy cron command or differing scan settings; migration stopped.'; return 1; }
        else
            [[ $rest == '/usr/bin/imunify-antivirus malware on-demand start --path /home' || $rest == '/usr/bin/imunify-antivirus malware on-demand start --path=/home' ||
               $rest == 'imunify-antivirus malware on-demand start --path /home' || $rest == 'imunify-antivirus malware on-demand start --path=/home' ]] || { error 'Unmanaged root scan: review and migrate it before installing.'; return 1; }
        fi
        found=$((found+1))
        ((found<=1)) || { error 'Multiple scan entries require review before migration.'; return 1; }
    done < "$file"
}

manager_main() {
    local action=${1:-install} update=false verify=false refresh=false user_override= dependency path help_file desired group uid user mode stage_config
    shift || true
    MIGRATE_CRON=
    while (($#)); do
        case $1 in
            --update) update=true;; --verify) verify=true;; --refresh-cron) refresh=true;;
            --notification-user) shift; user_override=${1:?Missing notification user};;
            --migrate-cron) shift; MIGRATE_CRON=${1:?Missing cron file};;
            -h|--help) printf 'Usage: install.sh [--update] [--verify] [--notification-user NAME] [--refresh-cron] [--migrate-cron FILE]\n'; return 0;;
            *) error 'Unknown installer option.'; return 1;;
        esac
        shift
    done
    [[ $action == install || $action == uninstall ]] || return 1
    [[ $(uname -s) == Linux && $EUID == 0 ]] || { error 'Run as root on Linux.'; return 1; }
    [[ ${BASH_VERSINFO[0]} -ge 4 ]] || { error 'Bash 4 or newer is required.'; return 1; }
    for dependency in jq curl flock sha256sum stat crontab getent runuser mktemp cp mv chmod chown find awk sed; do need "$dependency" || return 1; done
    AGENT=$(command -v imunify-antivirus) || { error 'Install ImunifyAV first.'; return 1; }
    if [[ $verify == true ]]; then notification_verify; return $?; fi
    [[ -d $CRON_DIR ]] || { error 'Install cron/cronie with cron.d support.'; return 1; }
    if [[ $action == install ]] && command -v systemctl >/dev/null; then
        systemctl is-active --quiet crond 2>/dev/null || systemctl is-active --quiet cron 2>/dev/null || { error 'Enable cron (Ubuntu) or crond (AlmaLinux).'; return 1; }
    fi
    trusted_path "$CONFIG"; trusted_path "$CRON"
    if [[ -d $CONFIG ]]; then while IFS= read -r -d '' path; do trusted_path "$path"; done < <(find "$CONFIG" -mindepth 1 -print0); fi
    "$AGENT" notifications-config update --help >/dev/null 2>&1 || { error 'Agent lacks notifications-config update.'; return 1; }
    if [[ $action == install ]]; then
        help_file=$("$AGENT" malware on-demand start --help 2>/dev/null) || return 1
        for dependency in --path --no-follow-symlinks --intensity-cpu --intensity-io; do [[ $help_file == *"$dependency"* ]] || { error 'Agent lacks required scan options.'; return 1; }; done
    fi
    exec 9>"$RUN_DIR/imunify-discord-install.lock"
    flock -n 9 || { error 'Another installer is running.'; return 1; }
    umask 077
    STAGE='notification and file backup'; COMMITTED=false; NOTIFY_TOUCHED=false; FILES_TOUCHED=false; ROOT_CRON_TOUCHED=false; LEGACY_TOUCHED=false
    OLD_TARGETS=$(notification_show)
    BACKUP=$(mktemp -d)
    trap 'manager_exit $?' EXIT
    trap 'exit 130' HUP INT TERM
    [[ ! -d $CONFIG ]] || cp -a -- "$CONFIG" "$BACKUP/config"
    [[ ! -f $CRON ]] || cp -a -- "$CRON" "$BACKUP/cron"
    if [[ $action == uninstall ]]; then
        STAGE='notification removal'; desired=$(notification_desired true <<< "$OLD_TARGETS")
        NOTIFY_TOUCHED=true; notification_apply "$desired"
        FILES_TOUCHED=true; rm -f -- "$CRON"
        for path in alert.py alert.sh alert.jq scan.py scan.sh common.sh agent; do rm -f -- "$CONFIG/$path"; done
        COMMITTED=true; printf 'Uninstalled. Webhook, configuration and private duplicate state retained.\n'; return 0
    fi
    STAGE='identity and configuration validation'
    user=${user_override:-_imunify}; uid=$(id -u "$user") || { error 'Notifier user missing; pass --notification-user after verifying its identity.'; return 1; }
    group=$(getent group _imunify | cut -d: -f3) || group=
    group=${group:-$(id -g "$user")}
    [[ $uid == 0 || " $(id -G "$user") " == *" $group "* ]] || { error 'Notifier does not belong to configuration access group.'; return 1; }
    if [[ $update == true && ! -f $CONFIG/webhook ]]; then error 'No existing webhook. Run install.sh first.'; return 1; fi
    stage_config=$CONFIG/config.env
    [[ -f $stage_config ]] || stage_config=$MANAGER_BASE/config.example.env
    read_config "$stage_config"
    STAGE='existing cron validation'
    if ! crontab -l > "$BACKUP/root-crontab" 2> "$BACKUP/crontab-error"; then
        grep -q 'no crontab for' "$BACKUP/crontab-error" || { error 'Cannot read root crontab.'; return 1; }
    fi
    filter_cron "$BACKUP/root-crontab" false > "$BACKUP/new-root-crontab"
    if [[ -n $MIGRATE_CRON ]]; then
        [[ ${MIGRATE_CRON%/*} == "$CRON_DIR" && $MIGRATE_CRON != "$CRON" && -f $MIGRATE_CRON ]] || { error 'Select another regular file directly inside /etc/cron.d.'; return 1; }
        trusted_path "$MIGRATE_CRON"
        cp -a -- "$MIGRATE_CRON" "$BACKUP/legacy-cron"
        filter_cron "$MIGRATE_CRON" true > "$BACKUP/new-legacy-cron"
    fi
    for path in "$CRON_DIR"/*; do
        [[ -f $path && $path != "$CRON" && $path != "$MIGRATE_CRON" ]] || continue
        if awk '!/^[[:space:]]*#/ && /imunify-antivirus/ && /on-demand/ && /\/home/ {found=1} END {exit !found}' "$path"; then
            error "Unmanaged scan in $path; select it explicitly with --migrate-cron FILE."; return 1
        fi
    done
    STAGE='secure webhook loading'
    if [[ -f $CONFIG/webhook ]]; then WEBHOOK=$(< "$CONFIG/webhook")
    else
        [[ -r /dev/tty && -w /dev/tty ]] || { error 'Run interactively to enter a hidden webhook.'; return 1; }
        IFS= read -r -s -p 'Discord webhook (hidden): ' WEBHOOK < /dev/tty || return 1
        printf '\n' > /dev/tty
    fi
    valid_webhook "$WEBHOOK" || { error 'Invalid HTTPS Discord webhook format; no query parameters allowed.'; return 1; }
    STAGE='Bash runtime installation'; FILES_TOUCHED=true
    mkdir -p -- "$CONFIG"; chown "0:$group" "$CONFIG"; chmod 750 "$CONFIG"
    if [[ ! -f $CONFIG/webhook ]]; then printf '%s\n' "$WEBHOOK" > "$BACKUP/webhook"; atomic_file "$BACKUP/webhook" "$CONFIG/webhook" 640 "$group"; fi
    chown "0:$group" "$CONFIG/webhook"; chmod 640 "$CONFIG/webhook"
    [[ -f $CONFIG/config.env ]] || atomic_file "$stage_config" "$CONFIG/config.env" 640 "$group"
    chown "0:$group" "$CONFIG/config.env"; chmod 640 "$CONFIG/config.env"
    for path in common.sh alert.sh scan.sh; do atomic_file "$MANAGER_BASE/scripts/$path" "$CONFIG/$path" 750 "$group"; done
    atomic_file "$MANAGER_BASE/scripts/alert.jq" "$CONFIG/alert.jq" 640 "$group"
    # Preserve the registered path for upgrades; this executable is Bash, not Python.
    printf '#!/bin/bash\nexec /etc/imunify-discord/alert.sh "$@"\n' > "$BACKUP/hook-wrapper"
    atomic_file "$BACKUP/hook-wrapper" "$CONFIG/alert.py" 750 "$group"
    printf '%s\n' "$AGENT" > "$BACKUP/agent"; atomic_file "$BACKUP/agent" "$CONFIG/agent" 640 "$group"
    STAGE='notifier access and private state'
    [[ ! -L $STATE ]] || { error 'Refusing symbolic link for duplicate state.'; return 1; }
    if [[ -e $STATE ]]; then
        [[ -d $STATE ]] || { error 'Duplicate state must be a directory.'; return 1; }
        path=$(stat -c %u -- "$STATE")
        [[ $path == 0 || $path == "$uid" ]] || { error 'Untrusted duplicate state owner.'; return 1; }
    else mkdir -p -- "$STATE"; fi
    chown "$uid:$(id -g "$user")" "$STATE"; chmod 700 "$STATE"
    runuser -u "$user" -- test -r "$CONFIG/webhook"
    runuser -u "$user" -- test -x "$CONFIG/alert.sh"
    runuser -u "$user" -- test -w "$STATE"
    STAGE='both malware event registrations'; desired=$(notification_desired false <<< "$OLD_TARGETS")
    NOTIFY_TOUCHED=true; notification_apply "$desired"
    STAGE='cron migration'
    if ! cmp -s "$BACKUP/root-crontab" "$BACKUP/new-root-crontab"; then ROOT_CRON_TOUCHED=true; crontab "$BACKUP/new-root-crontab"; fi
    if [[ -n $MIGRATE_CRON ]] && ! cmp -s "$BACKUP/legacy-cron" "$BACKUP/new-legacy-cron"; then
        LEGACY_TOUCHED=true; mode=$(stat -c %a -- "$MIGRATE_CRON"); path=$(stat -c %g -- "$MIGRATE_CRON")
        atomic_file "$BACKUP/new-legacy-cron" "$MIGRATE_CRON" "$mode" "$path"
    fi
    if [[ $update == true && -f $CRON && $refresh == false ]]; then
        # Only replace the old interpreter invocation; retain schedule and lock.
        sed -e 's@/usr/bin/python3 -I /etc/imunify-discord/scan.py@/bin/bash /etc/imunify-discord/scan.sh@g' \
            -e 's@/usr/bin/python3 /etc/imunify-discord/scan.py@/bin/bash /etc/imunify-discord/scan.sh@g' "$CRON" > "$BACKUP/new-cron"
        if grep -q '/etc/imunify-discord/scan.py' "$BACKUP/new-cron"; then error 'Unknown legacy scan invocation; review cron before switching to Bash.'; return 1; fi
    else
        printf '# Managed by imunify-discord; use --refresh-cron to apply schedule changes.\nSHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n%s root /usr/bin/flock -n /run/imunify-discord-scan.lock /bin/bash /etc/imunify-discord/scan.sh\n' "$SCAN_CRON" > "$BACKUP/new-cron"
    fi
    if [[ ! -f $CRON ]] || ! cmp -s "$CRON" "$BACKUP/new-cron"; then atomic_file "$BACKUP/new-cron" "$CRON" 644; fi
    rm -f -- "$CONFIG/scan.py"
    COMMITTED=true
    printf 'Installed/updated Bash runtime. Both malware events enabled; configuration and scan schedule preserved.\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then manager_main "$@"; fi
