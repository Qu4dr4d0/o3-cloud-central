#!/bin/sh
# Source/inline this file, then call o3c_native_gui_removal. Unknown means preserve.
# The POST-DEINSTALL package script must embed it; installed files are gone then.
o3c_native_gui_removal() (
 set -f
 IFS=' 	
'
 [ "${PKG_UPGRADE:-}" != true ] && [ "${O3C_PRESERVE_STATE:-}" != 1 ] && [ "${O3C_UNINSTALL_ACTIVE:-}" != 1 ] || return 1
 case "${PKG_ROOTDIR:-}" in ''|/) ;; *) return 1 ;; esac
 [ "${PKG_NAME:-}" = pfSense-pkg-O3CloudCentral ] || return 1
 o3c_gui_file=/var/run/pfSense-upgrade-GUI.pid
 o3c_upgrade=/usr/local/sbin/pfSense-upgrade
 for o3c_path in "$o3c_gui_file" "$o3c_upgrade"; do
  [ -f "$o3c_path" ] && [ ! -L "$o3c_path" ] || return 1
  o3c_meta=$(stat -f '%u %Lp' "$o3c_path" 2>/dev/null) || return 1
  set -- $o3c_meta
  [ "$#" -eq 2 ] && [ "$1" = 0 ] || return 1
  case "$2" in ''|*[!0-7]*) return 1 ;; esac
  [ "${#2}" -le 4 ] && [ "$((0$2 & 022))" -eq 0 ] || return 1
 done
 o3c_gui_snapshot=$(stat -f '%d:%i:%u:%Lp:%m' "$o3c_gui_file" 2>/dev/null) || return 1
 o3c_gui_pid=$(cat "$o3c_gui_file" 2>/dev/null) || return 1
 case "$o3c_gui_pid" in ''|*[!0-9]*) return 1 ;; esac
 [ "$o3c_gui_pid" -gt 1 ] 2>/dev/null || return 1
 o3c_pid=$$
 o3c_seen=' '
 for o3c_depth in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32; do
  case "$o3c_seen" in *" $o3c_pid "*) return 1 ;; esac
  o3c_seen="$o3c_seen$o3c_pid "
  o3c_row=$(ps -ww -p "$o3c_pid" -o ppid= -o uid= -o command= 2>/dev/null) || return 1
  set -- $o3c_row
  [ "$#" -ge 3 ] || return 1
  o3c_parent=$1
  [ "$2" = 0 ] || return 1
  case "$o3c_parent" in ''|*[!0-9]*) return 1 ;; esac
  shift 2
  if [ "$o3c_pid" = "$o3c_gui_pid" ]; then
   case "$1" in
    "$o3c_upgrade") shift ;;
    /bin/sh) shift; [ "$#" -ge 1 ] && [ "$1" = "$o3c_upgrade" ] || return 1; shift ;;
    *) return 1 ;;
   esac
   o3c_remove=0
   o3c_log=0
   o3c_socket=0
   o3c_yes=0
   while [ "$#" -gt 0 ]; do
    case "$1" in
     -y) [ "$o3c_yes" -eq 0 ] || return 1; o3c_yes=1; shift ;;
     -r) [ "$o3c_remove" -eq 0 ] && [ "$#" -ge 2 ] && [ "$2" = pfSense-pkg-O3CloudCentral ] || return 1; o3c_remove=1; shift 2 ;;
     -l) [ "$o3c_log" -eq 0 ] && [ "$#" -ge 2 ] || return 1; case "$2" in /conf/pkg_log_pfSense-pkg-O3CloudCentral.txt|/cf/conf/pkg_log_pfSense-pkg-O3CloudCentral.txt) ;; *) return 1 ;; esac; o3c_log=1; shift 2 ;;
     -p) [ "$o3c_socket" -eq 0 ] && [ "$#" -ge 2 ] && [ "$2" = /tmp/pfSense-upgrade.sock ] || return 1; o3c_socket=1; shift 2 ;;
     *) return 1 ;;
    esac
   done
   [ "$o3c_remove" -eq 1 ] || return 1
   [ "$(cat "$o3c_gui_file" 2>/dev/null)" = "$o3c_gui_pid" ] || return 1
   [ "$(stat -f '%d:%i:%u:%Lp:%m' "$o3c_gui_file" 2>/dev/null)" = "$o3c_gui_snapshot" ] || return 1
   return 0
  fi
  [ "$o3c_parent" -gt 1 ] 2>/dev/null || return 1
  o3c_pid=$o3c_parent
 done
 return 1
)
