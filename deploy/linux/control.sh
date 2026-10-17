#!/bin/sh
set -eu
help() {
 cat <<'HELP'
O3 Cloud Central — agente Linux
  sudo o3cloudcentral-agent status     Ver estado
  sudo o3cloudcentral-agent start      Conectar
  sudo o3cloudcentral-agent stop       Parar até iniciar ou reiniciar a máquina
  sudo o3cloudcentral-agent restart    Reconectar
  sudo o3cloudcentral-agent log        Ver os últimos 100 registros
  sudo o3cloudcentral-agent uninstall  Remover o agente desta máquina
  o3cloudcentral-agent help            Mostrar esta ajuda
O serviço inicia automaticamente com o Linux. A remoção local mantém o registro na central.
HELP
}
case "${1:-status}" in
 help|-h|--help) help ;;
 status) exec systemctl --no-pager status o3cloudcentral-agent.service ;;
 start|connect) exec systemctl start o3cloudcentral-agent.service ;;
 stop|disconnect) exec systemctl stop o3cloudcentral-agent.service ;;
 restart|reconnect) exec systemctl restart o3cloudcentral-agent.service ;;
 log) exec journalctl -u o3cloudcentral-agent.service -n 100 --no-pager ;;
 uninstall) exec /usr/local/sbin/o3cloudcentral-agent-uninstall ;;
 *) echo 'Comando desconhecido. Para remover: sudo o3cloudcentral-agent uninstall' >&2; help >&2; exit 1 ;;
esac
