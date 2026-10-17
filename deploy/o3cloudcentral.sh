#!/bin/sh
# PROVIDE: o3cloudcentral
# REQUIRE: NETWORKING
# KEYWORD: shutdown
# O3 Cloud Central preserves the private identity and shared PID files.
. /etc/rc.subr
name="o3cloudcentral"
rcvar="o3cloudcentral_enable"
command="/usr/sbin/daemon"
procname="/usr/sbin/daemon"
pidfile="/var/run/edgehub-supervisor.pid"
required_files="/usr/local/etc/edgehub/config.json"
command_args="-f -u _edgehub -r -R 5 -H -P ${pidfile} -p /var/run/edgehub.pid -o /var/log/edgehub.log /usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/edgehub/config.json"
o3cloudcentral_precmd() {
 install -d -m 700 /usr/local/etc/edgehub
 if ! pw groupshow _edgehub >/dev/null 2>&1; then
  pw groupadd _edgehub
  touch /usr/local/etc/edgehub/managed-group
  chmod 600 /usr/local/etc/edgehub/managed-group
 fi
 if ! pw usershow _edgehub >/dev/null 2>&1; then
  pw useradd _edgehub -g _edgehub -d /nonexistent -s /usr/sbin/nologin -w no
  touch /usr/local/etc/edgehub/managed-user
  chmod 600 /usr/local/etc/edgehub/managed-user
 fi
 install -d -m 750 -o root -g _edgehub /usr/local/etc/edgehub
 chown root:_edgehub /usr/local/etc/edgehub/config.json
 chmod 640 /usr/local/etc/edgehub/config.json
 install -d -m 700 -o _edgehub -g _edgehub /var/db/edgehub
 install -d -m 755 /var/etc/newsyslog.conf.d
 install -m 644 /usr/local/etc/newsyslog.conf.d/edgehub.conf /var/etc/newsyslog.conf.d/edgehub.conf
}
start_precmd="o3cloudcentral_precmd"
load_rc_config "$name"
: ${o3cloudcentral_enable:="${edgehub_enable:-YES}"}
run_rc_command "${1:-start}"
