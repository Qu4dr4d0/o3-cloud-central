<?php
/* Private O3 package integration. Never use killall on the shared interpreter. */
function o3c_process_matches($args, $role) {
    if ($role === 'child') {
        return preg_match('~^(/usr/local/sbin/o3cloudcentral|/usr/local/libexec/o3cloudcentral/runtime/bin/python3[.]12 -B -m o3cloudcentral) gateway --config /usr/local/etc/o3cloudcentral/config[.]json$~D', $args) === 1;
    }
    return preg_match('~^(daemon: /usr/local/sbin/o3cloudcentral\[[0-9]+\] \(daemon\)|/usr/sbin/daemon .* /usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config[.]json)$~D', $args) === 1;
}

function o3c_pid_state($path, $role) {
    clearstatcache(true, $path);
    if (!file_exists($path) && !is_link($path)) { return 'stopped'; }
    if (is_link($path) || !is_file($path)) { return 'unknown'; }
    $raw = trim((string)@file_get_contents($path));
    if (!preg_match('/^[0-9]{1,10}$/D', $raw) || (int)$raw <= 1) { return 'unknown'; }
    $lines = [];
    exec('/bin/ps -ww -p ' . escapeshellarg($raw) . ' -o command= 2>/dev/null', $lines, $rc);
    if ($rc === 1 && !$lines) { return 'stopped'; }
    if ($rc !== 0 || count($lines) !== 1) { return 'unknown'; }
    return o3c_process_matches(trim($lines[0]), $role) ? 'running' : 'unknown';
}

function o3c_service_state() {
    $child = o3c_pid_state('/var/run/o3cloudcentral.pid', 'child');
    $supervisor = o3c_pid_state('/var/run/o3cloudcentral-supervisor.pid', 'supervisor');
    if ($child === 'unknown' || $supervisor === 'unknown') { return 'unknown'; }
    if ($child === 'running') { return 'running'; }
    return $supervisor === 'running' ? 'restarting' : 'stopped';
}

function o3c_service_start() {
    $path = '/usr/local/etc/o3cloudcentral/config.json';
    if (is_link($path) || !is_file($path)) { return false; }
    $lock = '/var/run/o3cloudcentral-update.lock';
    if (!@mkdir($lock, 0700)) { return false; }
    try {
        $state = o3c_service_state();
        if ($state === 'running' || $state === 'restarting') { return true; }
        if ($state === 'unknown') { return false; }
        $output = [];
        exec('/usr/local/etc/rc.d/o3cloudcentral.sh start 2>&1', $output, $rc);
        return $rc === 0;
    } finally { @rmdir($lock); }
}

function o3c_service_stop() {
    // The outer updater/uninstaller already stopped the verified processes.
    if (getenv('O3C_PRESERVE_STATE') === '1' || getenv('O3C_UNINSTALL_ACTIVE') === '1') { return true; }
    $output = [];
    exec('/usr/local/sbin/o3cloudcentral-uninstall --stop-only 2>&1', $output, $rc);
    return $rc === 0;
}

function o3c_service_resync() {
    if (getenv('O3C_PRESERVE_STATE') === '1' || getenv('O3C_UNINSTALL_ACTIVE') === '1') { return; }
    if (is_file('/usr/local/etc/o3cloudcentral/config.json') && !is_link('/usr/local/etc/o3cloudcentral/config.json')) {
        o3c_service_start();
    }
}

function o3c_public_config() {
    $path = '/usr/local/etc/o3cloudcentral/config.json';
    if (is_link($path) || !is_file($path) || filesize($path) > 131072) { return []; }
    $config = json_decode((string)@file_get_contents($path), true);
    if (!is_array($config)) { return []; }
    $public = [];
    foreach (['id', 'listen', 'url'] as $key) {
        if (isset($config[$key]) && is_string($config[$key])) { $public[$key] = substr($config[$key], 0, 512); }
    }
    return $public;
}
