<?php
/*
 * O3 Cloud Central
 * ##|+PRIV
 * ##|*IDENT=page-services-o3cloudcentral
 * ##|*NAME=Services: O3 Cloud Central
 * ##|*DESCR=Controlar o agente O3 Cloud Central
 * ##|*MATCH=o3cloudcentral_status.php*
 * ##|-PRIV
 */
require_once('guiconfig.inc');
require_once('/usr/local/pkg/o3cloudcentral.inc');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $ok = false;
    if ($action === 'start') { $ok = o3c_service_start(); }
    if ($action === 'stop') { $ok = o3c_service_stop(); }
    if ($action === 'restart') { $ok = o3c_service_stop() && o3c_service_start(); }
    header('Location: /o3cloudcentral_status.php?result=' . ($ok ? 'ok' : 'error'));
    exit;
}
$pgtitle = [gettext('Services'), 'O3 Cloud Central'];
include('head.inc');
if (($_GET['result'] ?? '') === 'ok') { print_info_box('Comando executado.', 'success'); }
if (($_GET['result'] ?? '') === 'error') { print_info_box('Não foi possível executar. Confira se o agente está instalado e configurado ou se existe outra operação em andamento.', 'danger'); }
$state = o3c_service_state();
$labels = ['running' => 'Em execução', 'stopped' => 'Parado', 'restarting' => 'Reconectando', 'unknown' => 'Estado não confirmado'];
$colors = ['running' => 'success', 'stopped' => 'danger', 'restarting' => 'warning', 'unknown' => 'warning'];
$public = o3c_public_config();
?>
<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title"><img src="/o3cloudcentral-logo.png" alt="" height="28"> O3 Cloud Central</h2></div>
  <div class="panel-body">
    <p>Serviço <span class="label label-<?=htmlspecialchars($colors[$state])?>"><?=htmlspecialchars($labels[$state])?></span></p>
    <?php if (!$public): ?>
      <p>Aguardando configuração. Execute o comando de instalação gerado na central.</p>
    <?php else: ?>
      <dl class="dl-horizontal">
        <?php foreach (['id' => 'Cliente', 'listen' => 'Escuta', 'url' => 'Central'] as $key => $label): ?>
        <dt><?=htmlspecialchars($label)?></dt><dd><?=htmlspecialchars($public[$key] ?? '—')?></dd>
        <?php endforeach; ?>
      </dl>
    <?php endif; ?>
    <form method="post">
      <button type="submit" class="btn btn-success" name="action" value="start" <?=!$public || $state === 'unknown' ? 'disabled' : ''?>>Iniciar</button>
      <button type="submit" class="btn btn-warning" name="action" value="stop">Parar</button>
      <button type="submit" class="btn btn-primary" name="action" value="restart" <?=!$public || $state === 'unknown' ? 'disabled' : ''?>>Reiniciar</button>
      <a class="btn btn-default" href="/o3cloudcentral_status.php">Atualizar estado</a>
    </form>
  </div>
</div>
<?php print_info_box('Para desinstalar, acesse System → Package Manager → Installed Packages e clique na lixeira de pfSense-pkg-O3CloudCentral.'); ?>
<?php include('foot.inc'); ?>
