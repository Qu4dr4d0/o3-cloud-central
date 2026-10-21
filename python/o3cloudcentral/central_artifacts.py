"""Artifact delivery and minimal pfSense bootstrap commands.

Enrollment secrets are short lived; packages are validated before changing a service.
The executable trailer remains compatible with existing O3CloudCentral installers.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shlex
import struct
from pathlib import Path
from typing import Any, Iterator

INSTALLER_MAGIC = b"O3CC001!"
MAX_ARTIFACT = 128 << 20
DEFAULT_PFSENSE_PACKAGE = "pfSense-pkg-O3CloudCentral-0.7.2.pkg"
PFSENSE_PLATFORM = "pfSense CE 2.7.x / 2.8.x / 2.9.x amd64"

# Only these application-owned paths are snapshotted/removed by update recovery.
# Configuration is backed up separately. The live policy cache is never removed
# or rolled back, so a revocation received by the new process remains effective.
PFSENSE_OWNED_PATHS = (
    "usr/local/sbin/o3cloudcentral",
    "usr/local/sbin/o3cloudcentral-uninstall",
    "usr/local/etc/rc.d/o3cloudcentral.sh",
    "usr/local/etc/newsyslog.conf.d/o3cloudcentral.conf",
    "usr/local/share/licenses/o3cloudcentral/THIRD_PARTY_NOTICES.txt",
    "usr/local/libexec/o3cloudcentral",
    "usr/local/share/pfSense-pkg-O3CloudCentral/info.xml",
    "usr/local/pkg/o3cloudcentral.xml",
    "usr/local/pkg/o3cloudcentral.inc",
    "usr/local/www/o3cloudcentral_status.php",
    "usr/local/www/o3cloudcentral-logo.png",
)


def checked_artifact(path: Path) -> Path:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_ARTIFACT:
        raise ValueError("artefato indisponível ou inválido")
    return path


def package_digest(path: Path) -> str:
    checked_artifact(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bundle_bytes(bundle: dict[str, Any]) -> bytes:
    return json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def windows_installer_stream(path: Path, bundle: dict[str, Any]) -> Iterator[bytes]:
    raw = bundle_bytes(bundle)
    if len(raw) > 65536:
        raise ValueError("cadastro muito grande")
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            yield chunk
    yield raw
    yield struct.pack("<Q", len(raw)) + INSTALLER_MAGIC


def _q(value: str) -> str:
    return shlex.quote(value)


def _update_setup_steps() -> list[str]:
    owned = " ".join(PFSENSE_OWNED_PATHS)
    # Fixed absolute destinations are intentional. Never recursively remove a
    # computed path or trust package metadata to decide what a rollback deletes.
    restore = " ".join([
        "edge_rollback() { edge_recovery=0;",
        'edge_rc=/usr/local/etc/rc.d/o3cloudcentral.sh; if [ ! -e "$edge_rc" ]; then edge_rc=/usr/local/etc/rc.d/o3cloudcentral.sh; fi;',
        'if [ ! -f "$edge_rc" ] || [ -L "$edge_rc" ] || ! edge_pidfiles_safe owned; then echo "PID ou servico sem identidade confirmada. Nada sera restaurado; preserve o backup: $edge_backup" >&2; return 1; fi;',
        '"$edge_rc" stop >/dev/null 2>&1 || true;',
        '"$edge_rc" status >/dev/null 2>&1; edge_stop_status=$?;',
        'if [ "$edge_stop_status" -ne 1 ] || ! edge_pidfiles_safe stopped || ! edge_no_orphans; then echo "Servico nao parou ou estado nao confirmado. Arquivos, pacote e configuracao atuais foram preservados. Recuperacao administrativa necessaria; backup: $edge_backup" >&2; return 1; fi;',
        'if [ -n "$edge_previous_pkg" ]; then pkg add -f "$edge_previous_pkg" || edge_recovery=1; if [ "$edge_previous_repo" = pfSense ]; then pkg annotate -y -A "$edge_previous_name" repository pfSense || edge_recovery=1; fi; else for edge_name in pfSense-pkg-O3CloudCentral; do if pkg info -e "$edge_name" >/dev/null 2>&1; then pkg delete -fy "$edge_name" || edge_recovery=1; fi; done; fi;',
        'for edge_path in ' + owned + '; do if [ "$edge_path" = usr/local/libexec/o3cloudcentral ]; then rm -rf -- /usr/local/libexec/o3cloudcentral || edge_recovery=1; else rm -f -- "/$edge_path" || edge_recovery=1; fi; done;',
        'tar -xpf "$edge_backup/owned.tar" -C / || edge_recovery=1;',
        'edge_restore_config=$(mktemp /usr/local/etc/o3cloudcentral/.restore.XXXXXX) || edge_recovery=1;',
        'if [ -n "$edge_restore_config" ]; then if cp -p "$edge_backup/config.json" "$edge_restore_config" && mv -f "$edge_restore_config" /usr/local/etc/o3cloudcentral/config.json; then :; else edge_recovery=1; rm -f "$edge_restore_config"; fi; fi;',
        'if [ "$edge_was_running" -eq 1 ]; then /usr/local/etc/rc.d/o3cloudcentral.sh start && /usr/local/etc/rc.d/o3cloudcentral.sh status || edge_recovery=1; fi;',
        'if [ "$edge_recovery" -eq 0 ]; then echo "Atualizacao cancelada; instalacao anterior restaurada. Backup protegido: $edge_backup" >&2; else echo "Falha na recuperacao automatica. Preserve o backup protegido: $edge_backup" >&2; fi;',
        "}",
    ])
    cleanup = " ".join([
        "edge_cleanup() { edge_result=$?; trap - EXIT; trap '' HUP INT TERM; set +e;",
        'if [ "$edge_committed" -eq 0 ]; then if [ "$edge_dirty" -eq 1 ]; then edge_rollback; elif [ "$edge_stopped" -eq 1 ] && [ "$edge_was_running" -eq 1 ]; then /usr/local/etc/rc.d/o3cloudcentral.sh start || echo "Reinicie o O3 Cloud Central; os arquivos originais foram preservados." >&2; fi; fi;',
        'rm -f "$edge_tmp/ca.crt" "$edge_tmp/package.pkg"; rmdir "$edge_tmp";',
        'if [ "$edge_committed" -eq 1 ] && [ -n "$edge_backup" ]; then case "$edge_backup" in /var/tmp/o3cloudcentral-rollback.??????) rm -f "$edge_backup/owned.tar" "$edge_backup/config.json" "$edge_backup/paths"; if [ -n "$edge_previous_pkg" ]; then rm -f "$edge_previous_pkg"; fi; rmdir "$edge_backup/package" "$edge_backup" ;; *) echo "Backup preservado para revisao: $edge_backup" >&2 ;; esac; fi;',
        'rmdir "$edge_lock";',
        'exit "$edge_result"; }',
    ])
    return [
        '[ -f /usr/local/etc/o3cloudcentral/config.json ] && [ ! -L /usr/local/etc/o3cloudcentral/config.json ] || { echo "Instalacao local nao encontrada. No painel, use Reinstalar pfSense para este cliente." >&2; exit 1; }',
        '[ -d /usr/local/etc/o3cloudcentral ] && [ ! -L /usr/local/etc/o3cloudcentral ] || { echo "Diretorio de configuracao invalido." >&2; exit 1; }',
        '[ -f /usr/local/sbin/o3cloudcentral ] && [ ! -L /usr/local/sbin/o3cloudcentral ] || { echo "Executavel existente nao encontrado." >&2; exit 1; }',
        '[ -f /usr/local/etc/rc.d/o3cloudcentral.sh ] && [ ! -L /usr/local/etc/rc.d/o3cloudcentral.sh ] || { echo "Servico existente nao encontrado." >&2; exit 1; }',
        '[ ! -L /usr/local/libexec/o3cloudcentral ] && { [ ! -e /usr/local/libexec/o3cloudcentral ] || [ -d /usr/local/libexec/o3cloudcentral ]; } || { echo "Runtime privado invalido." >&2; exit 1; }',
        'edge_lock=/var/run/o3cloudcentral-update.lock',
        'mkdir -m 700 "$edge_lock" || { echo "Outra atualizacao O3 Cloud Central esta em andamento. Verifique /var/run/o3cloudcentral-update.lock." >&2; exit 1; }',
        'edge_tmp=""', 'edge_backup=""', 'edge_previous_pkg=""', 'edge_previous_name=""', 'edge_previous_repo=""', 'edge_restore_config=""',
        'edge_was_running=0', 'edge_stopped=0', 'edge_started=0', 'edge_dirty=0', 'edge_committed=0',
        *_process_guard_steps(), restore, cleanup, 'trap edge_cleanup EXIT', "trap 'exit 1' HUP INT TERM",
        'edge_tmp=$(mktemp -d /tmp/o3cloudcentral-update.XXXXXX)',
    ]


def _process_guard_steps() -> list[str]:
    """A nonzero rc status alone cannot prove a PID is absent or belongs to us."""
    pid_guard = " ".join([
        'edge_pidfiles_safe() { edge_pid_mode=$1;',
        'for edge_pid_file in /var/run/o3cloudcentral-supervisor.pid /var/run/o3cloudcentral.pid; do',
        'if [ ! -e "$edge_pid_file" ] && [ ! -L "$edge_pid_file" ]; then continue; fi;',
        '[ -f "$edge_pid_file" ] && [ ! -L "$edge_pid_file" ] || return 1;',
        'edge_pid=$(cat "$edge_pid_file" 2>/dev/null) || return 1;',
        'case "$edge_pid" in ""|*[!0-9]*) return 1 ;; esac; [ "$edge_pid" -gt 1 ] 2>/dev/null || return 1;',
        'edge_pid_args=$(ps -ww -p "$edge_pid" -o command= 2>/dev/null); edge_ps_status=$?;',
        'if [ "$edge_ps_status" -eq 1 ]; then continue; fi;',
        '[ "$edge_ps_status" -eq 0 ] && [ -n "$edge_pid_args" ] || return 1;',
        '[ "$edge_pid_mode" != stopped ] || return 1;',
        'case "$edge_pid_file:$edge_pid_args" in',
        '/var/run/o3cloudcentral-supervisor.pid:"daemon: /usr/local/sbin/o3cloudcentral["*"] (daemon)"|/var/run/o3cloudcentral-supervisor.pid:"daemon: /usr/local/sbin/o3cloudcentral["*"] (daemon)"|/var/run/o3cloudcentral-supervisor.pid:"/usr/sbin/daemon "*" /usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json"|/var/run/o3cloudcentral-supervisor.pid:"/usr/sbin/daemon "*" /usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json") ;;',
        '/var/run/o3cloudcentral.pid:"/usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json"|/var/run/o3cloudcentral.pid:"/usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json"|/var/run/o3cloudcentral.pid:"/usr/local/libexec/o3cloudcentral/runtime/bin/python3.12 -B -m o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json") ;;',
        '*) return 1 ;; esac; done; return 0; }',
    ])
    orphan_guard = " ".join([
        'edge_no_orphans() {',
        "pgrep -f '^daemon: /usr/local/sbin/o3cloudcentral\\[[0-9]+\\] \\(daemon\\)$' >/dev/null 2>&1; edge_scan_status=$?; [ \"$edge_scan_status\" -eq 1 ] || return 1;",
        "pgrep -f '^/usr/sbin/daemon .* /usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config[.]json$' >/dev/null 2>&1; edge_scan_status=$?; [ \"$edge_scan_status\" -eq 1 ] || return 1;",
        "pgrep -f '^(/usr/local/sbin/o3cloudcentral|/usr/local/libexec/o3cloudcentral/runtime/bin/python3[.]12 -B -m o3cloudcentral) gateway --config /usr/local/etc/o3cloudcentral/config[.]json$' >/dev/null 2>&1; edge_scan_status=$?; [ \"$edge_scan_status\" -eq 1 ] || return 1;",
        'return 0; }',
    ])
    return [pid_guard, orphan_guard]


def _update_apply_steps(url: str) -> list[str]:
    owned = " ".join(PFSENSE_OWNED_PATHS)
    return [
        'edge_backup=$(mktemp -d /var/tmp/o3cloudcentral-rollback.XXXXXX)',
        'chmod 700 "$edge_backup"',
        'mkdir -m 700 "$edge_backup/package"',
        'if /usr/local/etc/rc.d/o3cloudcentral.sh status >/dev/null 2>&1; then edge_was_running=1; edge_stopped=1; /usr/local/etc/rc.d/o3cloudcentral.sh stop; fi',
        ': > "$edge_backup/paths"',
        'for edge_path in ' + owned + '; do if [ -e "/$edge_path" ] || [ -L "/$edge_path" ]; then printf "%s\\n" "$edge_path" >> "$edge_backup/paths"; fi; done',
        'tar -cpf "$edge_backup/owned.tar" -C / -T "$edge_backup/paths"',
        'cp -p /usr/local/etc/o3cloudcentral/config.json "$edge_backup/config.json"',
        # Rebuilding the original installed package preserves pkg's ownership
        # database as well as the direct file snapshot if migration fails.
        'for edge_name in pfSense-pkg-O3CloudCentral; do if pkg info -e "$edge_name" >/dev/null 2>&1; then [ -z "$edge_previous_name" ] || { echo "Duas instalacoes registradas. Revise antes de atualizar." >&2; exit 1; }; edge_previous_name=$edge_name; fi; done',
        'if [ -n "$edge_previous_name" ]; then edge_previous_repo=$(pkg query %R "$edge_previous_name"); fi',
        'if [ -n "$edge_previous_name" ]; then pkg create -o "$edge_backup/package" "$edge_previous_name"; set -- "$edge_backup/package/"*.pkg; [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "Nao foi possivel criar pacote de recuperacao." >&2; exit 1; }; edge_previous_pkg=$1; fi',
        'edge_dirty=1',
        'pkg add -f "$edge_tmp/package.pkg"',
        'pkg annotate -y -A pfSense-pkg-O3CloudCentral repository pfSense',
        '/usr/local/sbin/o3cloudcentral configure-gateway --config /usr/local/etc/o3cloudcentral/config.json --url ' + _q(url),
        'edge_started=1',
        '/usr/local/etc/rc.d/o3cloudcentral.sh start',
        '/usr/local/etc/rc.d/o3cloudcentral.sh status',
        'edge_committed=1',
    ]


def pfsense_command(bundle: dict[str, Any], checksum: str, *, update: bool = False, replace_site_id: str = "") -> str:
    if bundle.get("kind") != ("gateway-update" if update else "gateway"):
        raise ValueError("tipo de cadastro inválido")
    if replace_site_id and (update or not isinstance(replace_site_id, str) or len(replace_site_id) > 100 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in replace_site_id)):
        raise ValueError("cliente de reinstalação inválido")
    if len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
        raise ValueError("checksum inválido")
    url = bundle["url"].rstrip("/")
    download = url + "/api/install/pfsense/" + bundle["token"] + "/package"
    ca = base64.b64encode(bundle["ca"].encode()).decode()
    raw = base64.b64encode(bundle_bytes(bundle)).decode()
    steps = [
        "set -eu",
        '[ "$(id -u)" -eq 0 ] || { echo "Execute como root no pfSense." >&2; exit 1; }',
        'case "$(uname -s):$(uname -m):$(uname -r)" in FreeBSD:amd64:14.*|FreeBSD:amd64:15.*|FreeBSD:amd64:16.*) ;; *) echo "Requer pfSense CE 2.7.x, 2.8.x ou 2.9.x amd64 (FreeBSD 14, 15 ou 16)." >&2; exit 1 ;; esac',
        "umask 077",
        "export O3C_PRESERVE_STATE=1",
    ]
    if update:
        steps.extend(_update_setup_steps())
    elif replace_site_id:
        steps.extend([
            'edge_lock=/var/run/o3cloudcentral-update.lock', 'edge_locked=0', 'edge_tmp=""',
            'edge_cleanup() { edge_result=$?; trap - EXIT; trap \'\' HUP INT TERM; set +e; if [ -n "$edge_tmp" ]; then rm -f "$edge_tmp/ca.crt" "$edge_tmp/enrollment.json" "$edge_tmp/package.pkg" "$edge_tmp/uninstall.sh" || edge_result=1; rmdir "$edge_tmp" || edge_result=1; fi; if [ "$edge_locked" -eq 1 ]; then rmdir "$edge_lock" || edge_result=1; fi; exit "$edge_result"; }',
            'trap edge_cleanup EXIT',
            'edge_tmp=$(mktemp -d /tmp/o3cloudcentral-install.XXXXXX)',
        ])
    else:
        steps.extend([
            'edge_lock=/var/run/o3cloudcentral-update.lock',
            'mkdir -m 700 "$edge_lock" || { echo "Outra instalacao, atualizacao ou remocao esta em andamento." >&2; exit 1; }',
            'edge_tmp=""',
            'edge_cleanup() { edge_result=$?; trap - EXIT; trap \'\' HUP INT TERM; set +e; if [ -n "$edge_tmp" ]; then rm -f "$edge_tmp/ca.crt" "$edge_tmp/enrollment.json" "$edge_tmp/package.pkg" || edge_result=1; rmdir "$edge_tmp" || edge_result=1; fi; rmdir "$edge_lock" || edge_result=1; exit "$edge_result"; }',
            'trap edge_cleanup EXIT',
            '[ ! -e /usr/local/etc/o3cloudcentral/config.json ] && [ ! -L /usr/local/etc/o3cloudcentral/config.json ] || { echo "Ja existe configuracao local. Remova o pacote em Installed Packages antes de cadastrar outro cliente." >&2; exit 1; }',
            'edge_tmp=$(mktemp -d /tmp/o3cloudcentral-install.XXXXXX)',
        ])
    steps.extend([
        "trap 'exit 1' HUP INT TERM",
        "printf %s " + _q(ca) + ' | openssl enc -base64 -d -A > "$edge_tmp/ca.crt"',
        "fetch --ca-cert=\"$edge_tmp/ca.crt\" -T 60 -o \"$edge_tmp/package.pkg\" " + _q(download),
        '[ "$(sha256 -q "$edge_tmp/package.pkg")" = ' + _q(checksum) + ' ] || { echo "Pacote alterado ou download invalido. Gere novo comando." >&2; exit 1; }',
    ])
    if update:
        steps.extend(_update_apply_steps(url))
    else:
        if replace_site_id:
            steps.extend([
                'tar -xOf "$edge_tmp/package.pkg" /usr/local/sbin/o3cloudcentral-uninstall > "$edge_tmp/uninstall.sh"',
                'test -s "$edge_tmp/uninstall.sh"',
                '/bin/sh "$edge_tmp/uninstall.sh" --replace-client ' + _q(replace_site_id),
                'mkdir -m 700 "$edge_lock" || { echo "Outra operacao assumiu o firewall. A nova configuracao foi preservada; gere outro comando." >&2; exit 1; }',
                'edge_locked=1',
                '[ ! -e /usr/local/etc/o3cloudcentral/config.json ] && [ ! -L /usr/local/etc/o3cloudcentral/config.json ] || { echo "Outra instalacao criou uma identidade. Configuracao preservada." >&2; exit 1; }',
            ])
        steps.extend([
            "printf %s " + _q(raw) + ' | openssl enc -base64 -d -A > "$edge_tmp/enrollment.json"',
            'pkg add -f "$edge_tmp/package.pkg"',
            'pkg annotate -y -A pfSense-pkg-O3CloudCentral repository pfSense',
            "install -d -m 700 /usr/local/etc/o3cloudcentral",
            '/usr/local/sbin/o3cloudcentral enroll --bundle "$edge_tmp/enrollment.json" --config /usr/local/etc/o3cloudcentral/config.json',
            "/usr/local/etc/rc.d/o3cloudcentral.sh start",
        ])
    if not update:
        steps.append("/usr/local/etc/rc.d/o3cloudcentral.sh status")
    steps.append('echo "O3 Cloud Central instalado/atualizado. Confira o estado no painel."')
    return "/bin/sh -c " + _q("; ".join(steps))
