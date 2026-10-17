#!/bin/sh
# Remove only O3 Cloud Central and its legacy installation. No firewall/SSH changes.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Execute como root no pfSense.' >&2; exit 1; }
edge_mode=full
edge_expected_client=''
case "$#" in
 0) ;;
 1) case "$1" in --stop-only) edge_mode=stop ;; --native-cleanup) edge_mode=native ;; *) echo 'Modo de remocao invalido.' >&2; exit 1 ;; esac ;;
 2) [ "$1" = --replace-client ] || { echo 'Modo de remocao invalido.' >&2; exit 1; }; case "$2" in ''|*[!a-zA-Z0-9_-]*) echo 'Cliente invalido.' >&2; exit 1 ;; esac; edge_expected_client=$2 ;;
 *) echo 'Modo de remocao invalido.' >&2; exit 1 ;;
esac
# Native hooks preserve identity for replacement, nested removal and chroots.
if [ "$edge_mode" = native ]; then
 [ "${PKG_UPGRADE:-}" != true ] && [ "${O3C_PRESERVE_STATE:-}" != 1 ] && [ "${O3C_UNINSTALL_ACTIVE:-}" != 1 ] || exit 0
 case "${PKG_ROOTDIR:-}" in ''|/) ;; *) exit 0 ;; esac
fi

edge_fail() { echo "$* Remocao nao concluida." >&2; exit 1; }
edge_lock=/var/run/edgehub-update.lock
mkdir -m 700 "$edge_lock" || edge_fail 'Outra instalacao, atualizacao ou remocao esta em andamento.'
trap 'rmdir "$edge_lock" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM

# Reinstallation may only replace this customer's local identity. Validate
# under the shared lifecycle lock, before stopping processes or deleting data.
if [ -n "$edge_expected_client" ] && { [ -e /usr/local/etc/edgehub/config.json ] || [ -L /usr/local/etc/edgehub/config.json ]; }; then
 [ -d /usr/local/etc/edgehub ] && [ ! -L /usr/local/etc/edgehub ] && [ -f /usr/local/etc/edgehub/config.json ] && [ ! -L /usr/local/etc/edgehub/config.json ] || edge_fail 'Configuracao local invalida; arquivos preservados.'
 /usr/local/bin/php -r '$p="/usr/local/etc/edgehub/config.json"; if(filesize($p)>131072){exit(1);} $c=json_decode(file_get_contents($p),true); exit(is_array($c) && ($c["kind"]??"")==="gateway" && ($c["id"]??"")===$argv[1] ? 0 : 1);' "$edge_expected_client" || edge_fail 'Este firewall pertence a outro cliente ou possui configuracao invalida; instalacao preservada.'
fi

edge_user_owned=0
edge_group_owned=0
if [ -d /usr/local/etc/edgehub ] && [ ! -L /usr/local/etc/edgehub ]; then
 [ ! -f /usr/local/etc/edgehub/managed-user ] || [ -L /usr/local/etc/edgehub/managed-user ] || edge_user_owned=1
 [ ! -f /usr/local/etc/edgehub/managed-group ] || [ -L /usr/local/etc/edgehub/managed-group ] || edge_group_owned=1
fi

edge_supervisor_pattern='^(daemon: /usr/local/sbin/(edgehub|o3cloudcentral)\[[0-9]+\] \(daemon\)|/usr/sbin/daemon .* /usr/local/sbin/(edgehub|o3cloudcentral) gateway --config /usr/local/etc/edgehub/config[.]json)$'
edge_child_pattern='^(/usr/local/sbin/(edgehub|o3cloudcentral)|/usr/local/libexec/edgehub/runtime/bin/python3[.]12 -B -m edgehub) gateway --config /usr/local/etc/edgehub/config[.]json$'

# 0 = verified product process, 1 = absent, 2 = unknown/unrelated/error.
edge_process() {
 case "$1" in ''|*[!0-9]*) return 2 ;; esac
 [ "$1" -gt 1 ] 2>/dev/null || return 2
 if edge_proc_args=$(ps -ww -p "$1" -o command= 2>/dev/null); then
  [ -n "$edge_proc_args" ] || return 2
 else
  edge_proc_status=$?
  [ "$edge_proc_status" -eq 1 ] && return 1
  return 2
 fi
 case "$2" in supervisor) edge_proc_pattern=$edge_supervisor_pattern ;; child) edge_proc_pattern=$edge_child_pattern ;; *) return 2 ;; esac
 printf '%s\n' "$edge_proc_args" | grep -Eq "$edge_proc_pattern" && return 0
 return 2
}

edge_pidfile() {
 if [ ! -e "$1" ] && [ ! -L "$1" ]; then return 0; fi
 [ -f "$1" ] && [ ! -L "$1" ] || { echo "Arquivo PID invalido: $1." >&2; return 1; }
 edge_file_pid=$(cat "$1") || return 1
 if edge_process "$edge_file_pid" "$2"; then
  printf '%s\n' "$edge_file_pid"
 else
  edge_file_status=$?
  [ "$edge_file_status" -eq 1 ] || { echo "PID em $1 sem identidade confirmada." >&2; return 1; }
 fi
}

edge_scan() {
 if edge_scan_pids=$(pgrep -f "$1" 2>/dev/null); then
  [ -n "$edge_scan_pids" ] || return 1
 else
  edge_scan_status=$?
  [ "$edge_scan_status" -eq 1 ] && return 0
  echo 'Falha ao consultar os processos.' >&2
  return 1
 fi
 for edge_scan_pid in $edge_scan_pids; do
  if edge_process "$edge_scan_pid" "$2"; then
   printf '%s\n' "$edge_scan_pid"
  else
   edge_scan_status=$?
   [ "$edge_scan_status" -eq 1 ] || { echo 'Processo sem identidade confirmada.' >&2; return 1; }
  fi
 done
}

edge_collect() {
 edge_supervisor_file=$(edge_pidfile /var/run/edgehub-supervisor.pid supervisor) || return 1
 edge_child_file=$(edge_pidfile /var/run/edgehub.pid child) || return 1
 edge_supervisor_scan=$(edge_scan "$edge_supervisor_pattern" supervisor) || return 1
 edge_child_scan=$(edge_scan "$edge_child_pattern" child) || return 1
 edge_supervisors="$edge_supervisor_file $edge_supervisor_scan"
 edge_children="$edge_child_file $edge_child_scan"
}

edge_signal() {
 if edge_process "$1" "$2"; then
  if kill "-$3" "$1" 2>/dev/null; then return 0; fi
  if edge_process "$1" "$2"; then return 1; else [ "$?" -eq 1 ]; fi
 else
  [ "$?" -eq 1 ]
 fi
}

edge_collect || edge_fail 'Processos e arquivos foram preservados.'
echo 'Parando somente os processos O3 Cloud Central...'
for edge_pid in $edge_supervisors; do edge_signal "$edge_pid" supervisor TERM || edge_fail 'Supervisor nao confirmado/parado.'; done
for edge_pid in $edge_children; do edge_signal "$edge_pid" child TERM || edge_fail 'Agente nao confirmado/parado.'; done
for edge_attempt in 1 2 3 4 5 6 7 8 9 10; do
 edge_collect || edge_fail 'Nao foi possivel confirmar os processos.'
 [ -n "$(printf '%s%s' "$edge_supervisors" "$edge_children" | tr -d '[:space:]')" ] || break
 sleep 1
done
for edge_pid in $edge_supervisors; do edge_signal "$edge_pid" supervisor KILL || edge_fail 'Supervisor nao confirmado/parado.'; done
for edge_pid in $edge_children; do edge_signal "$edge_pid" child KILL || edge_fail 'Agente nao confirmado/parado.'; done
for edge_attempt in 1 2 3 4 5; do
 edge_collect || edge_fail 'Nao foi possivel confirmar o encerramento.'
 [ -n "$(printf '%s%s' "$edge_supervisors" "$edge_children" | tr -d '[:space:]')" ] || break
 sleep 1
done
[ -z "$(printf '%s%s' "$edge_supervisors" "$edge_children" | tr -d '[:space:]')" ] || edge_fail 'Processo ainda ativo; configuracao e pacote preservados.'
if [ "$edge_mode" = stop ]; then
 rmdir "$edge_lock"
 trap - EXIT HUP INT TERM
 echo 'Servico O3 Cloud Central parado.'
 exit 0
fi

# pkg may unlink this running script. Its open shell descriptor remains valid;
# all cleanup and verification below must run before reporting success.
edge_package_present() {
 if pkg info -e "$1" >/dev/null 2>&1; then return 0; else edge_pkg_status=$?; fi
 [ "$edge_pkg_status" -eq 1 ] && return 1
 return 2
}
if [ "$edge_mode" = full ]; then
 for edge_package in pfSense-pkg-O3CloudCentral pfSense-pkg-EdgeHub; do
  if edge_package_present "$edge_package"; then
   O3C_UNINSTALL_ACTIVE=1 pkg delete -y -f "$edge_package" || edge_fail "Nao foi possivel remover $edge_package."
  else
   [ "$?" -eq 1 ] || edge_fail 'Banco de pacotes nao confirmado.'
  fi
 done
 for edge_package in pfSense-pkg-O3CloudCentral pfSense-pkg-EdgeHub; do
  if edge_package_present "$edge_package"; then edge_fail "Pacote ainda registrado: $edge_package."; else [ "$?" -eq 1 ] || edge_fail 'Banco de pacotes nao confirmado.'; fi
 done
fi

# Fixed product paths only. rm removes a symlink itself, never its target.
rm -f /usr/local/sbin/edgehub /usr/local/sbin/edgehub-uninstall /usr/local/etc/rc.d/edgehub.sh
rm -f /usr/local/sbin/o3cloudcentral /usr/local/sbin/o3cloudcentral-uninstall /usr/local/etc/rc.d/o3cloudcentral.sh
rm -f /usr/local/etc/newsyslog.conf.d/edgehub.conf /var/etc/newsyslog.conf.d/edgehub.conf
rm -f /var/run/edgehub-supervisor.pid /var/run/edgehub.pid
rm -f /var/log/edgehub.log /var/log/edgehub.log.[0-9]*
rm -f /usr/local/pkg/o3cloudcentral.xml /usr/local/pkg/o3cloudcentral.inc /usr/local/www/o3cloudcentral_status.php /usr/local/www/o3cloudcentral-logo.png
rm -rf /usr/local/etc/edgehub /var/db/edgehub
# pkg removes its registered directories AFTER POST-DEINSTALL. Leave those
# directories to pkg, otherwise its final unlinkat pass emits false warnings.
if [ "$edge_mode" = full ]; then
 rm -rf /usr/local/share/licenses/edgehub /usr/local/libexec/edgehub /usr/local/share/pfSense-pkg-O3CloudCentral
fi
if [ "$edge_user_owned" -eq 1 ] && pw usershow _edgehub >/dev/null 2>&1; then
 if pgrep -u _edgehub >/dev/null 2>&1; then
  echo 'Conta _edgehub preservada: ainda possui processos.'
 else
  [ "$?" -eq 1 ] || edge_fail 'Processos da conta _edgehub nao confirmados.'
  pw userdel _edgehub
 fi
fi
if [ "$edge_group_owned" -eq 1 ] && edge_group_record=$(pw groupshow _edgehub 2>/dev/null); then
 edge_gid=$(printf '%s\n' "$edge_group_record" | cut -d: -f3)
 edge_members=$(printf '%s\n' "$edge_group_record" | cut -d: -f4)
 case "$edge_gid" in ''|*[!0-9]*) edge_fail 'Identidade do grupo _edgehub nao confirmada.' ;; esac
 edge_users=$(pw usershow -a) || edge_fail 'Usuarios do grupo _edgehub nao confirmados.'
 if [ -z "$edge_members" ] && ! printf '%s\n' "$edge_users" | awk -F: -v gid="$edge_gid" '$4 == gid {found=1} END {exit !found}'; then
  pw groupdel _edgehub
 else
  echo 'Grupo _edgehub preservado: ainda possui usuarios.'
 fi
fi

edge_collect || edge_fail 'Nao foi possivel verificar o encerramento final.'
[ -z "$(printf '%s%s' "$edge_supervisors" "$edge_children" | tr -d '[:space:]')" ] || edge_fail 'Processo O3 Cloud Central reapareceu.'
for edge_path in /usr/local/etc/edgehub /var/db/edgehub /usr/local/libexec/edgehub /usr/local/share/licenses/edgehub /usr/local/share/pfSense-pkg-O3CloudCentral /usr/local/pkg/o3cloudcentral.xml /usr/local/pkg/o3cloudcentral.inc /usr/local/www/o3cloudcentral_status.php /usr/local/www/o3cloudcentral-logo.png /usr/local/sbin/edgehub /usr/local/sbin/edgehub-uninstall /usr/local/sbin/o3cloudcentral /usr/local/sbin/o3cloudcentral-uninstall /usr/local/etc/rc.d/edgehub.sh /usr/local/etc/rc.d/o3cloudcentral.sh /usr/local/etc/newsyslog.conf.d/edgehub.conf /var/etc/newsyslog.conf.d/edgehub.conf /var/run/edgehub-supervisor.pid /var/run/edgehub.pid /var/log/edgehub.log /var/log/edgehub.log.[0-9]*; do
 if [ "$edge_mode" = native ]; then
  case "$edge_path" in /usr/local/libexec/edgehub|/usr/local/share/licenses/edgehub|/usr/local/share/pfSense-pkg-O3CloudCentral) continue ;; esac
 fi
 [ ! -e "$edge_path" ] && [ ! -L "$edge_path" ] || edge_fail "Arquivo ainda presente: $edge_path."
done
if [ "$edge_mode" = full ]; then
 for edge_package in pfSense-pkg-O3CloudCentral pfSense-pkg-EdgeHub; do
  if edge_package_present "$edge_package"; then edge_fail "Pacote ainda registrado: $edge_package."; else [ "$?" -eq 1 ] || edge_fail 'Banco de pacotes nao confirmado.'; fi
 done
fi
rmdir "$edge_lock"
trap - EXIT HUP INT TERM
echo 'O3 Cloud Central removido deste pfSense. O cadastro do cliente permanece na central.'
