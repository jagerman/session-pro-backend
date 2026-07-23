#!/bin/bash
#
# Scheduled pgBackRest backup — runs ON THE REPOSITORY host as the pgbackrest user (via the
# pro-backend-backup.timer that repo-host-setup.sh installs). Full on Sundays, differential
# otherwise; WAL is archived continuously between runs by the primary's archive_command.
set -euo pipefail

STANZA=session_pro
CONFIG=/etc/pgbackrest/session_pro.conf
if [[ "$(date +%u)" == "7" ]]; then
    backup_type="full"
else
    backup_type="diff"
fi
echo "Running pgBackRest $backup_type backup for stanza $STANZA"
pgbackrest --config="$CONFIG" --stanza="$STANZA" --type="$backup_type" backup
echo "Backup complete."
