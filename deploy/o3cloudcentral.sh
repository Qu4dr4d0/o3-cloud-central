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
pidfile="/var/run/o3cloudcentral-supervisor.pid"
required_files="/usr/local/etc/o3cloudcentral/config.json"
command_args="-f -u _o3cloudcentral -r -R 5 -H -P ${pidfile} -p /var/run/o3cloudcentral.pid -o /var/log/o3cloudcentral.log /usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json"
o3cloudcentral_precmd() {
 install -d -m 700 /usr/local/etc/o3cloudcentral
 if ! pw groupshow _o3cloudcentral >/dev/null 2>&1; then
  pw groupadd _o3cloudcentral
  touch /usr/local/etc/o3cloudcentral/managed-group
  chmod 600 /usr/local/etc/o3cloudcentral/managed-group
 fi
 if ! pw usershow _o3cloudcentral >/dev/null 2>&1; then
  pw useradd _o3cloudcentral -g _o3cloudcentral -d /nonexistent -s /usr/sbin/nologin -w no
  touch /usr/local/etc/o3cloudcentral/managed-user
  chmod 600 /usr/local/etc/o3cloudcentral/managed-user
 fi
 install -d -m 750 -o root -g _o3cloudcentral /usr/local/etc/o3cloudcentral
 chown root:_o3cloudcentral /usr/local/etc/o3cloudcentral/config.json
 chmod 640 /usr/local/etc/o3cloudcentral/config.json
 install -d -m 700 -o _o3cloudcentral -g _o3cloudcentral /var/db/o3cloudcentral
 install -d -m 755 /var/etc/newsyslog.conf.d
 install -m 644 /usr/local/etc/newsyslog.conf.d/o3cloudcentral.conf /var/etc/newsyslog.conf.d/o3cloudcentral.conf
}
start_precmd="o3cloudcentral_precmd"
load_rc_config "$name"
: ${o3cloudcentral_enable:="YES"}
run_rc_command "${1:-start}"
