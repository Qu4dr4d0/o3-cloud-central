#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Execute como root ou use sudo.' >&2; exit 1; }
lock=/run/o3cloudcentral-agent-install.lock
mkdir -m 700 "$lock" || { echo 'Outra instalação ou remoção do agente está em andamento.' >&2; exit 1; }
trap 'rmdir "$lock"' EXIT
trap 'exit 1' HUP INT TERM
unit=/etc/systemd/system/o3cloudcentral-agent.service
if [ -e "$unit" ] || [ -L "$unit" ]; then
 [ -f "$unit" ] && [ ! -L "$unit" ] && grep -q '^# Managed by O3 Cloud Central terminal installer$' "$unit" || { echo 'Unidade sem identidade confirmada; arquivos preservados.' >&2; exit 1; }
 systemctl stop o3cloudcentral-agent.service
 if systemctl is-active --quiet o3cloudcentral-agent.service; then echo 'O serviço ainda está ativo; remoção cancelada.' >&2; exit 1; else status=$?; [ "$status" -eq 3 ] || [ "$status" -eq 4 ]; fi
 systemctl disable o3cloudcentral-agent.service
fi
owned_user=0; owned_group=0
for marker in managed-user managed-group; do
 path=/var/lib/o3cloudcentral-agent/$marker
 if [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c %u "$path")" = 0 ]; then
  case "$marker" in managed-user) owned_user=1 ;; managed-group) owned_group=1 ;; esac
 fi
done
rm -f -- /etc/systemd/system/o3cloudcentral-agent.service /usr/local/bin/o3cloudcentral-agent /usr/local/sbin/o3cloudcentral-agent-uninstall
rm -rf -- /opt/o3cloudcentral-agent /var/lib/o3cloudcentral-agent
systemctl daemon-reload
systemctl reset-failed o3cloudcentral-agent.service >/dev/null 2>&1 || true
if [ "$owned_user" -eq 1 ] && id _o3cloudagent >/dev/null 2>&1; then
 if pgrep -u _o3cloudagent >/dev/null 2>&1; then echo 'Conta preservada: ainda possui processos.'; else [ "$?" -eq 1 ]; userdel _o3cloudagent; fi
fi
if [ "$owned_group" -eq 1 ] && getent group _o3cloudagent >/dev/null; then
 groupdel _o3cloudagent 2>/dev/null || echo 'Grupo preservado: ainda está em uso.'
fi
for path in /opt/o3cloudcentral-agent /var/lib/o3cloudcentral-agent /etc/systemd/system/o3cloudcentral-agent.service /usr/local/bin/o3cloudcentral-agent /usr/local/sbin/o3cloudcentral-agent-uninstall; do
 [ ! -e "$path" ] && [ ! -L "$path" ] || { echo 'Remoção incompleta.' >&2; exit 1; }
done
echo 'O3 Cloud Central removido deste terminal. O cadastro permanece na central.'
