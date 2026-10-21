const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const root=path.resolve(__dirname,'..'),now=new Date().toISOString(),old='2025-01-01T00:00:00Z';
 const state={version:'Prévia de layout',now,sites:{
 lab:{cidrs:['172.30.20.0/24'],id:'lab',name:'Cliente Laboratório',endpoint:'ddns.exemplo.com:2222',host_key:'fixture',last_seen:now,services:[{id:'web',name:'Nginx laboratório',target:'172.30.20.10',port:80,local_port:18080,protocol:'TCP'}],report:{sessions:{connected:1},services:[{id:'web',reachable:true,checked_at:now}]}},
 fresh:{id:'fresh',name:'Cliente sem pfSense',endpoint:'novo.exemplo.com:2222',host_key:'',last_seen:old,services:[],report:{}},
 other:{id:'other',name:'Outro cliente',endpoint:'outro.exemplo.com:2222',host_key:'fixture',last_seen:old,services:[],report:{}}
 },devices:{
 connected:{id:'connected',site_id:'lab',name:'Caixa ativo',hostname:'CAIXA-01',local_ip:'192.168.10.21',os:'windows',agent_version:'0.4.0-lab',services:['web'],public_key:'fixture',last_seen:now,revoked:false},
 offline:{id:'offline',site_id:'lab',name:'Caixa offline',hostname:'CAIXA-02',local_ip:'192.168.10.22',os:'linux',services:['web'],public_key:'fixture',last_seen:old,revoked:false},
 pending:{id:'pending',site_id:'lab',name:'Terminal pendente',services:['web'],public_key:'',last_seen:old,revoked:false},
 revoked:{id:'revoked',site_id:'lab',name:'Terminal removido',services:['web'],public_key:'fixture',last_seen:now,revoked:true},
 cross:{id:'cross',site_id:'other',name:'Terminal de outro cliente',services:[],public_key:'fixture',last_seen:old,revoked:false}
 }};
 state.sites.lab.gateway_status={state:'online',online:true,reason:'Contato e receptor confirmados.'};
 state.sites.fresh.gateway_status={state:'pending',online:false};state.sites.other.gateway_status={state:'offline',online:false};
 state.sites.lab.policy_sync='applied';
 state.sites.lab.services[0].availability='accessible';state.devices.connected.online=true;
 let terminalBody=null,serviceBody=null,passwordBody=null,clientBody=null,stateGets=0,failState=false,endpointBody=null,removedServices=0,removedClients=0,failClientDelete=false,linkBody=null,generatedLinks=0,revokedLinks=0,reinstallRequests=0,failReinstall=false;
 const server=http.createServer((req,res)=>{
  res.setHeader('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if(req.url==='/api/admin/state'){stateGets++;if(failState){res.writeHead(503);res.end('offline fixture');return}state.now=new Date().toISOString();res.setHeader('Content-Type','application/json');res.end(JSON.stringify(state));return}
  if(req.method==='DELETE'&&req.url==='/api/admin/sites/lab/install-link'){
   revokedLinks++;state.sites.lab.installation_link=null;res.setHeader('Content-Type','application/json');res.end('{"ok":true}');return;
  }
  if(req.method==='DELETE'&&req.url==='/api/admin/sites/automatic'){
   if(failClientDelete){res.writeHead(500);res.end('Falha ao remover cliente.');return}
   removedClients++;delete state.sites.automatic;
   for(const [id,d] of Object.entries(state.devices))if(d.site_id==='automatic')delete state.devices[id];
   res.setHeader('Content-Type','application/json');res.end('{"ok":true}');return;
  }
  if(req.method==='DELETE'&&req.url==='/api/admin/sites/lab/services/db'){
   removedServices++;state.sites.lab.services=state.sites.lab.services.filter(s=>s.id!=='db');
   for(const d of Object.values(state.devices))if(d.site_id==='lab')d.services=d.services.filter(id=>id!=='db');
   res.setHeader('Content-Type','application/json');res.end('{"ok":true}');return;
  }
  if(req.method==='POST'||req.method==='PATCH'){
   let raw='';req.on('data',b=>raw+=b);req.on('end',()=>{
    const body=JSON.parse(raw);res.setHeader('Content-Type','application/json');
    if(req.method==='PATCH'&&req.url==='/api/admin/sites/lab'){
     if(body.endpoint==='invalido'){res.writeHead(400);res.end('endereço inválido');return}
     endpointBody=body;state.sites.lab.endpoint=body.endpoint;state.sites.lab.cidrs=body.cidrs;res.end('{"ok":true}');return;
    }
    if(req.url==='/api/admin/sites/lab/install-link'){
     linkBody=body;generatedLinks++;const link={id:'lnk_fixture_'+generatedLinks,services:body.services,created_at:now,expires_at:null,installation_count:0};if(body.platform==='debian'){state.sites.lab.installation_links={windows:state.sites.lab.installation_link,debian:link}}else{state.sites.lab.installation_link=link}res.end(JSON.stringify({...link,url:'https://novo.exemplo.com:2223/install/windows/reusable-'+generatedLinks,...(body.platform==='debian'?{command:"/bin/sh -c 'echo linux-fixture'"}:{})}));return;
    }
    if(req.url==='/api/admin/sites'){clientBody=body;state.sites.automatic={id:'automatic',...body,services:[],host_key:'',last_seen:old,report:{}};res.end(JSON.stringify(state.sites.automatic));return}
    if(req.url==='/api/admin/sites/lab/reinstall-command'||req.url==='/api/admin/sites/fresh/reinstall-command'){
     reinstallRequests++;if(failReinstall){res.writeHead(503);res.end('Falha ao gerar comando de reinstalação.');return}
     res.end(JSON.stringify({command:"/bin/sh -c 'echo fresh-install-fixture'",expires_at:new Date(Date.now()+900000).toISOString(),platform:'pfSense CE 2.7.x / 2.8.x / 2.9.x amd64'}));return;
    }
    if(req.url==='/api/admin/sites/fresh/install-command'||req.url==='/api/admin/sites/automatic/install-command'){res.end(JSON.stringify({command:"/bin/sh -c 'echo fixture'",expires_at:new Date(Date.now()+900000).toISOString(),platform:'pfSense CE 2.7.x / 2.8.x / 2.9.x amd64'}));return}
    if(req.url==='/api/admin/devices/pending/install-link'){res.end(JSON.stringify({url:'https://novo.exemplo.com:2222/install/windows/fixture-token',expires_at:new Date(Date.now()+86400000).toISOString()}));return}
    if(req.url==='/api/admin/devices'){terminalBody=body;state.devices.created={id:'created',name:'Novo terminal (fixture)',...body,public_key:'',revoked:false,last_seen:old};res.end(JSON.stringify(state.devices.created));return}
    if(req.url==='/api/admin/sites/lab/services'){serviceBody=body;const svc={id:'db',...body,local_port:20000};state.sites.lab.services.push(svc);res.end(JSON.stringify(svc));return}
    if(req.url==='/api/admin/account/password'){passwordBody=body;res.end('{"ok":true,"reauthenticate":true}');return}
    res.writeHead(404);res.end('{}');
   });return;
  }
  if(req.url==='/favicon.ico?v=6'||req.url==='/favicon.ico'){res.setHeader('Content-Type','image/x-icon');res.end(fs.readFileSync(path.join(root,'assets/O3CloudCentral.ico')));return}
  if(req.url==='/brand/logo.png'){res.setHeader('Content-Type','image/png');res.end(fs.readFileSync(path.join(root,'assets/O3CloudCentral.png')));return}
  const file={'/':'index.html','/app.js':'app.js','/theme.js':'theme.js','/style.css':'style.css'}[req.url];if(!file){res.writeHead(404);res.end();return}
  res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(path.join(root,'web',file)));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({channel:process.env.BROWSER_CHANNEL||'msedge',headless:true});
 try{
  const context=await browser.newContext({viewport:{width:1440,height:1100},colorScheme:'light'}),page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:'+server.address().port,{waitUntil:'networkidle'});
  await page.getByRole('heading',{name:'Clientes e serviços',exact:true}).waitFor();
  assert.equal(await page.title(),'O3 Cloud Central · Clientes');
  assert.equal(await page.locator('.brand strong').textContent(),'O3 Cloud Central');
  assert.equal(await page.locator('.brand-logo').getAttribute('src'),'/brand/logo.png');
  assert.equal(await page.locator('.brand-logo').evaluate(n=>n.complete&&n.naturalWidth>0),true);
  const theme=page.locator('#theme-toggle'),themeValue=()=>page.locator('html').getAttribute('data-theme');
  assert.equal(await themeValue(),'light');
  await theme.focus();await page.keyboard.press('Enter');
  assert.equal(await themeValue(),'dark');assert.equal(await theme.getAttribute('aria-pressed'),'true');
  const darkBackground=await page.locator('body').evaluate(n=>getComputedStyle(n).backgroundColor);
  assert.equal(darkBackground,'rgb(16, 23, 34)');
  await page.reload({waitUntil:'networkidle'});assert.equal(await themeValue(),'dark');
  await page.emulateMedia({colorScheme:'light'});assert.equal(await themeValue(),'dark');
  await page.screenshot({path:path.join(root,'dist/painel-escuro-desktop.png'),fullPage:true});
  await theme.click();await page.reload({waitUntil:'networkidle'});assert.equal(await themeValue(),'light');
  await page.evaluate(()=>localStorage.removeItem('o3cloudcentral-theme'));
  await page.emulateMedia({colorScheme:'dark'});await page.reload({waitUntil:'networkidle'});assert.equal(await themeValue(),'dark');
  await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='light');
  const other=await page.context().newPage();await other.goto(page.url(),{waitUntil:'networkidle'});
  await theme.click();await other.waitForFunction(()=>document.documentElement.dataset.theme==='dark');
  await theme.click();await other.waitForFunction(()=>document.documentElement.dataset.theme==='light');await other.close();
  const blocked=await browser.newPage({colorScheme:'dark'});
  blocked.on('pageerror',e=>errors.push(e.message));
  await blocked.addInitScript(()=>Object.defineProperty(window,'localStorage',{get(){throw new DOMException('Storage blocked','SecurityError')}}));
  await blocked.goto(page.url(),{waitUntil:'networkidle'});
  assert.equal(await blocked.locator('html').getAttribute('data-theme'),'dark');
  await blocked.locator('#theme-toggle').click();assert.equal(await blocked.locator('html').getAttribute('data-theme'),'light');await blocked.close();
  assert.equal(await page.locator('#client-view').isVisible(),false);assert.equal(await page.locator('#service-dialog').isVisible(),false);
  assert.equal(await page.locator('#active-count').textContent(),'1');assert.equal(await page.locator('#offline-count').textContent(),'2');
  await page.screenshot({path:path.join(root,'dist/painel-desktop.png'),fullPage:true});
  await page.evaluate(()=>{window.savedDateNow=Date.now;Date.now=()=>0;render()});
  assert.equal(await page.locator('#active-count').textContent(),'1');
  assert.equal(await page.getByText('pfSense conectado',{exact:true}).count(),1);
  await page.evaluate(()=>Date.now=window.savedDateNow);
  state.sites.lab.gateway_status={state:'offline',online:false,reason:'Receptor SSH indisponível.'};state.devices.connected.online=false;
  await page.evaluate(()=>refresh());
  assert.equal(await page.locator('#active-count').textContent(),'0');
  assert.equal(await page.getByText('pfSense conectado',{exact:true}).count(),0);
  assert.equal(await page.getByText('pfSense offline',{exact:true}).count(),2);
  state.sites.lab.gateway_status={state:'unknown',online:false};state.sites.lab.policy_sync='pending';state.devices.connected.connection_state='unknown';state.devices.offline.connection_state='unknown';
  await page.evaluate(()=>refresh());
  assert.equal(await page.getByText('Sem contato com pfSense',{exact:true}).count(),1);
  assert.equal(await page.locator('#offline-count').textContent(),'1');
  assert.equal(await page.getByText('Alterações pendentes no pfSense',{exact:true}).count(),1);
  delete state.devices.connected.connection_state;delete state.devices.offline.connection_state;state.sites.lab.policy_sync='applied';
  state.sites.lab.gateway_status={state:'online',online:true};state.devices.connected.online=true;
  failState=true;await page.evaluate(()=>refresh());
  assert.equal(await page.locator('#active-count').textContent(),'—');
  assert.equal(await page.getByText('pfSense conectado',{exact:true}).count(),0);
  assert.equal(await page.getByText('Sem atualização',{exact:true}).count(),3);
  failState=false;await page.evaluate(()=>refresh());
  assert.equal(await page.locator('#active-count').textContent(),'1');

  await page.getByRole('link',{name:'Abrir cliente Cliente sem pfSense',exact:true}).click();
  await page.getByRole('button',{name:'Gerar nova instalação',exact:true}).click();
  await page.locator('#gateway-install-dialog').waitFor({state:'visible'});
  assert.equal(await page.locator('#gateway-install-command').inputValue(),"/bin/sh -c 'echo fresh-install-fixture'");
  assert.equal(await page.locator('#gateway-install-identity-warning').isVisible(),false);
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async value=>{window.fixtureCopied=value}}}));
  await page.getByRole('button',{name:'Copiar comando',exact:true}).click();
  assert.equal(await page.evaluate(()=>window.fixtureCopied),"/bin/sh -c 'echo fresh-install-fixture'");
  await page.locator('#gateway-install-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  await page.waitForFunction(()=>document.querySelector('#gateway-install-command').value==='');
  assert.equal(await page.locator('#gateway-install-command').inputValue(),'');
  await page.getByRole('link',{name:'Todos os clientes',exact:false}).click();
  await page.getByRole('link',{name:'Abrir cliente Cliente Laboratório',exact:true}).click();
  await page.locator('#client-view').waitFor({state:'visible'});
  assert.equal(await page.getByRole('button',{name:'Comando de remoção',exact:true}).count(),0);
  assert.equal(await page.getByRole('button',{name:'Alterar endereço público',exact:true}).count(),0);
  assert.equal(await page.locator('#client-actions').getByRole('button',{name:'Remover cliente',exact:true}).count(),1);
  assert.equal(await page.locator('#client-actions button').count(),2);
  assert.equal(await page.getByRole('button',{name:'Atualizar pfSense',exact:true}).count(),0);
  assert.equal(await page.getByRole('button',{name:'Reinstalar pfSense',exact:true}).count(),0);
  const generatedBefore=reinstallRequests;
  await page.evaluate(()=>refresh());assert.equal(reinstallRequests,generatedBefore);
  failReinstall=true;await page.getByRole('button',{name:'Gerar nova instalação',exact:true}).click();
  await page.getByText('Falha ao gerar comando de reinstalação.',{exact:true}).waitFor();
  assert.equal(await page.locator('#gateway-install-dialog').isVisible(),false);
  failReinstall=false;await page.getByRole('button',{name:'Gerar nova instalação',exact:true}).click();
  await page.locator('#gateway-install-dialog').waitFor({state:'visible'});
  assert.equal(reinstallRequests,generatedBefore+2);
  assert.equal(await page.locator('#gateway-install-title').textContent(),'Nova instalação no pfSense');
  assert.match(await page.locator('#gateway-install-summary').textContent(),/não interrompe a conexão atual/);
  assert.match(await page.locator('#gateway-install-identity-warning').textContent(),/terminais já instalados precisarão/);
  assert.equal(await page.locator('#gateway-install-identity-warning').isVisible(),true);
  await page.evaluate(()=>refresh());assert.equal(reinstallRequests,generatedBefore+2);
  await page.locator('#gateway-install-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  await page.getByRole('button',{name:'Editar cliente',exact:true}).click();
  const endpointForm=page.locator('#endpoint-form');
  assert.equal(await endpointForm.locator('[name="endpoint"]').inputValue(),'ddns.exemplo.com:2222');
  assert.equal(await endpointForm.locator('[name="cidrs"]').inputValue(),'172.30.20.0/24');
  await page.locator('#endpoint-dialog').screenshot({path:path.join(root,'dist/editar-cliente-redes.png')});
  await endpointForm.locator('[name="endpoint"]').fill('invalido');
  await endpointForm.getByRole('button',{name:'Salvar alterações',exact:true}).click();
  await endpointForm.locator('[data-form-error]').waitFor({state:'visible'});assert.equal(endpointBody,null);
  await endpointForm.locator('[name="endpoint"]').fill('novo.exemplo.com:2223');
  await endpointForm.locator('[name="cidrs"]').fill('172.30.20.0/24, 192.168.20.0/24');
  await page.evaluate(()=>refresh());assert.equal(await endpointForm.locator('[name="endpoint"]').inputValue(),'novo.exemplo.com:2223');
  await endpointForm.getByRole('button',{name:'Salvar alterações',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#client-endpoint').textContent==='novo.exemplo.com:2223');
  assert.deepEqual(endpointBody,{endpoint:'novo.exemplo.com:2223',cidrs:['172.30.20.0/24','192.168.20.0/24']});
  await page.getByRole('button',{name:'Editar cliente',exact:true}).click();
  assert.equal(await endpointForm.locator('[name="endpoint"]').inputValue(),'novo.exemplo.com:2223');
  assert.equal(await endpointForm.locator('[name="cidrs"]').inputValue(),'172.30.20.0/24, 192.168.20.0/24');
  await endpointForm.getByRole('button',{name:'Cancelar',exact:true}).click();
  assert.equal(await page.locator('#devices tr').count(),2);
  assert.equal(await page.locator('#devices').getByText('Terminal removido').count(),0);
  assert.equal(await page.locator('#devices').getByText('Terminal de outro cliente').count(),0);
  assert.equal(await page.locator('#devices').getByText('Terminal pendente').count(),0);
  assert.equal(await page.locator('#devices').getByText('Ativo',{exact:true}).count(),1);
  assert.equal(await page.locator('#devices').getByText('Offline',{exact:true}).count(),1);
  assert.deepEqual(await page.locator('#devices').evaluate(n=>[...n.closest('table').querySelectorAll('th')].map(th=>th.textContent)),['Hostname','IP local','Sistema operacional','Estado','Serviços autorizados','Último contato','Ações']);
  assert.equal(await page.locator('#devices').getByText('CAIXA-01',{exact:true}).count(),1);
  assert.equal(await page.locator('#devices tr').filter({hasText:'CAIXA-01'}).locator('td').first().getAttribute('title'),'windows · O3 Cloud Central 0.4.0-lab');
  assert.equal(await page.locator('#devices').getByText('192.168.10.21',{exact:true}).count(),1);
  const permitted=page.locator('#devices tr').filter({hasText:'CAIXA-01'}).locator('td').nth(4);
  assert.equal(await permitted.textContent(),'Nginx laboratório');
  assert.equal(await page.locator('#devices').getByText('http://127.0.0.1:18080/',{exact:true}).count(),0);

  const offlineRow=page.locator('#devices tr').filter({hasText:'Caixa offline'});
  await offlineRow.getByRole('button',{name:'Comandos',exact:true}).click();
  assert.equal(await page.locator('#linux-command-list input').count(),7);
  assert.equal(await page.locator('#linux-command-list input').nth(5).inputValue(),'sudo o3cloudcentral-agent uninstall');
  await page.locator('#linux-commands-dialog').getByRole('button',{name:'Fechar',exact:true}).click();
  assert.equal(await offlineRow.locator('.badge.bad').textContent(),'Offline');
  const beforeAutomatic=stateGets;state.devices.offline.online=true;
  await offlineRow.getByText('Ativo',{exact:true}).waitFor({timeout:8000});
  assert.ok(stateGets>beforeAutomatic,'estado precisa consultar a central automaticamente');
  assert.equal(await page.locator('#active-count').textContent(),'2');
  state.devices.offline.online=false;
  await offlineRow.getByText('Offline',{exact:true}).waitFor({timeout:8000});
  assert.equal(await offlineRow.locator('.badge.bad').textContent(),'Offline');
  assert.equal(await page.locator('#active-count').textContent(),'1');

  assert.equal(await page.locator('#services a').first().getAttribute('href'),'http://127.0.0.1:18080/');
  assert.equal(await page.locator('#services a').first().getAttribute('target'),'_blank');
  await page.screenshot({path:path.join(root,'dist/painel-cliente-desktop.png'),fullPage:true});
  await theme.click();await page.screenshot({path:path.join(root,'dist/painel-cliente-escuro.png'),fullPage:true});
  await page.getByRole('button',{name:'Adicionar serviço',exact:true}).click();
  await page.locator('#service-dialog').screenshot({path:path.join(root,'dist/servico-escuro.png')});
  assert.equal(await page.locator('#service-dialog').evaluate(n=>getComputedStyle(n).backgroundColor),'rgb(25, 35, 49)');
  await page.locator('#service-dialog').getByRole('button',{name:'Cancelar',exact:true}).click();
  await theme.click();

  await page.locator('#pending-details').evaluate(d=>d.open=true);
  await page.getByRole('button',{name:'Gerar link de instalação',exact:true}).first().click();
  await page.locator('#terminal-link-dialog').waitFor({state:'visible'});
  assert.equal(await page.locator('#terminal-install-link').inputValue(),'https://novo.exemplo.com:2222/install/windows/fixture-token');
  await page.getByRole('button',{name:'Copiar link',exact:true}).click();
  assert.equal(await page.evaluate(()=>window.fixtureCopied),'https://novo.exemplo.com:2222/install/windows/fixture-token');
  await page.locator('#terminal-link-dialog').screenshot({path:path.join(root,'dist/link-instalacao.png')});
  await page.locator('#terminal-link-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  await page.waitForFunction(()=>document.querySelector('#terminal-install-link').value==='');
  assert.equal(await page.locator('#terminal-install-link').inputValue(),'');

  await page.getByRole('button',{name:'Adicionar serviço',exact:true}).click();
  const sf=page.locator('#service-form');assert.equal(await sf.locator('input[name="local_port"]').count(),0);assert.equal(await sf.locator('input,select').count(),4);
  assert.deepEqual(await sf.locator('select[name="type"] option').evaluateAll(nodes=>nodes.map(n=>n.value)),['HTTP','HTTPS','SSH','TCP']);
  assert.equal(await sf.locator('[name="port"]').inputValue(),'80');
  await sf.locator('[name="type"]').selectOption('HTTPS');assert.equal(await sf.locator('[name="port"]').inputValue(),'443');
  await sf.locator('[name="port"]').fill('8443');await sf.locator('[name="type"]').selectOption('SSH');assert.equal(await sf.locator('[name="port"]').inputValue(),'8443');
  await sf.locator('[name="port"]').fill('');await sf.locator('[name="type"]').selectOption('SSH');assert.equal(await sf.locator('[name="port"]').inputValue(),'22');
  await sf.locator('[name="type"]').selectOption('TCP');assert.equal(await sf.locator('[name="port"]').inputValue(),'');
  await sf.locator('[name="name"]').fill('Banco PostgreSQL');await sf.locator('[name="target"]').fill('172.30.20.10');await sf.locator('[name="port"]').fill('5432');
  await sf.getByRole('button',{name:'Adicionar serviço',exact:true}).click();
  await page.locator('#services').getByText('127.0.0.1:20000',{exact:true}).waitFor();
  assert.equal(serviceBody.type,'TCP');assert.equal(serviceBody.protocol,'TCP');assert.equal(serviceBody.port,5432);assert.equal('local_port' in serviceBody,false);
  await page.getByRole('button',{name:'Instalar terminais',exact:true}).click();
  const df=page.locator('#device-form');assert.equal(await df.locator('input[name="name"]').count(),0);
  await df.locator('input[value="selected"]').check();
  await df.getByRole('button',{name:'Gerar link',exact:true}).click();
  await df.locator('[data-form-error]').waitFor({state:'visible'});assert.equal(linkBody,null);
  await df.locator('input[value="web"]').check();
  await page.evaluate(()=>refresh());assert.equal(await df.locator('input[value="web"]').isChecked(),true);
  await df.getByRole('button',{name:'Gerar link',exact:true}).click();
  await page.locator('#terminal-link-dialog').waitFor({state:'visible'});
  assert.deepEqual(linkBody,{services:['web']});assert.equal(terminalBody,null);
  assert.equal(await page.locator('#terminal-install-link').inputValue(),'https://novo.exemplo.com:2223/install/windows/reusable-1');
  assert.match(await page.locator('#terminal-install-expiry').textContent(),/Várias máquinas/);
  assert.match(await page.locator('#terminal-install-rules').textContent(),/invalida/i);
  await page.getByRole('button',{name:'Copiar link',exact:true}).click();
  assert.equal(await page.evaluate(()=>window.fixtureCopied),'https://novo.exemplo.com:2223/install/windows/reusable-1');
  await page.locator('#terminal-link-dialog').screenshot({path:path.join(root,'dist/link-reutilizavel.png')});
  await page.locator('#terminal-link-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  state.sites.lab.installation_link.installation_count=2;await page.reload({waitUntil:'networkidle'});
  assert.equal(await page.locator('#terminal-install-link').inputValue(),'');
  assert.match(await page.locator('#client-install-link-status').textContent(),/2 instalações/);
  await page.getByRole('button',{name:'Instalar terminais',exact:true}).click();
  assert.match(await page.locator('#active-install-link-services').textContent(),/Nginx laboratório/);
  assert.match(await page.locator('#active-install-link-count').textContent(),/2/);
  await page.locator('#device-dialog').screenshot({path:path.join(root,'dist/instalar-terminais.png')});
  page.once('dialog',dialog=>dialog.dismiss());await df.getByRole('button',{name:'Gerar novo link',exact:true}).click();assert.equal(generatedLinks,1);
  page.once('dialog',dialog=>dialog.accept());await df.getByRole('button',{name:'Gerar novo link',exact:true}).click();
  await page.locator('#terminal-link-dialog').waitFor({state:'visible'});assert.equal(generatedLinks,2);
  await page.locator('#terminal-link-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  await page.getByRole('button',{name:'Instalar terminais',exact:true}).click();
  page.once('dialog',dialog=>dialog.dismiss());await page.locator('#revoke-client-link').click();assert.equal(revokedLinks,0);
  page.once('dialog',dialog=>dialog.accept());await page.locator('#revoke-client-link').click();
  await page.locator('#active-install-link').waitFor({state:'hidden'});assert.equal(revokedLinks,1);
  await df.locator('select[name="platform"]').selectOption('debian');
  await df.getByRole('button',{name:'Gerar link',exact:true}).click();
  await page.locator('#terminal-link-dialog').waitFor({state:'visible'});
  assert.equal(linkBody.platform,'debian');
  assert.equal(await page.locator('#terminal-install-command').inputValue(),"/bin/sh -c 'echo linux-fixture'");
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async value=>{window.fixtureCopied=value}}}));
  await page.locator('#copy-terminal-command').click();
  assert.equal(await page.evaluate(()=>window.fixtureCopied),"/bin/sh -c 'echo linux-fixture'");
  await page.locator('#terminal-link-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  await page.waitForFunction(()=>document.querySelector('#terminal-install-command').value==='');
  await page.getByRole('button',{name:'Instalar terminais',exact:true}).click();
  assert.equal(await page.locator('#devices tr').count(),2);
  await df.getByRole('button',{name:'Cancelar',exact:true}).click();
  page.once('dialog',dialog=>dialog.dismiss());
  await page.getByRole('button',{name:'Remover serviço Banco PostgreSQL',exact:true}).click();
  assert.equal(removedServices,0);
  await page.getByRole('button',{name:'Remover serviço Banco PostgreSQL',exact:true}).waitFor({state:'visible'});
  page.once('dialog',dialog=>dialog.accept());
  await page.getByRole('button',{name:'Remover serviço Banco PostgreSQL',exact:true}).click();
  await page.getByRole('button',{name:'Remover serviço Banco PostgreSQL',exact:true}).waitFor({state:'detached'});
  assert.equal(removedServices,1);assert.equal(await page.locator('#services').getByText('Nginx laboratório',{exact:true}).count(),1);
  await page.getByRole('button',{name:'Instalar terminais',exact:true}).click();
  assert.equal(await df.locator('input[value="db"]').count(),0);
  await df.getByRole('button',{name:'Cancelar',exact:true}).click();
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(root,'dist/painel-cliente-mobile.png'),fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await theme.click();await page.setViewportSize({width:320,height:740});
  await page.screenshot({path:path.join(root,'dist/painel-escuro-mobile.png'),fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await theme.click();await page.setViewportSize({width:390,height:844});
  await page.getByRole('link',{name:'Todos os clientes',exact:false}).click();
  await page.screenshot({path:path.join(root,'dist/painel-mobile.png'),fullPage:true});
  assert.equal(await page.locator('#client-view').isVisible(),false);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.getByRole('button',{name:'Cadastrar cliente',exact:true}).click();
  const cf=page.locator('#site-form');assert.equal(await cf.locator('input[name="listen"]').count(),1);assert.equal(await cf.locator('input').count(),4);
  await cf.locator('[name="name"]').fill('Cliente automático');await cf.locator('[name="endpoint"]').fill('novo.exemplo.com:2223');await cf.locator('[name="listen"]').fill('10.10.10.130:2222');await cf.locator('[name="cidrs"]').fill('172.30.30.0/24, 172.30.40.0/24');
  await page.locator('#client-dialog').screenshot({path:path.join(root,'dist/cadastro-cliente.png')});
  await cf.getByRole('button',{name:'Cadastrar cliente',exact:true}).click();
  await page.getByRole('heading',{name:'Cliente automático',exact:true}).waitFor();
  await page.locator('#gateway-install-dialog').waitFor({state:'visible'});
  assert.equal(await page.locator('#gateway-install-command').inputValue(),"/bin/sh -c 'echo fixture'");
  await page.locator('#gateway-install-dialog').getByRole('button',{name:'Fechar',exact:true}).last().click();
  assert.equal(clientBody.listen,'10.10.10.130:2222');assert.equal(clientBody.endpoint,'novo.exemplo.com:2223');assert.deepEqual(clientBody.cidrs,['172.30.30.0/24','172.30.40.0/24']);
  state.sites.automatic.services=[{id:'only',name:'Portal único',target:'172.30.30.10',port:80,local_port:20000,type:'HTTP',protocol:'TCP'}];
  await page.reload({waitUntil:'networkidle'});
  await page.getByRole('button',{name:'Instalar terminais',exact:true}).click();
  assert.equal(await page.locator('#device-form input[name="name"]').count(),0);
  assert.equal(await page.locator('#device-form input[value="all"]').isChecked(),true);
  await page.locator('#device-form').getByRole('button',{name:'Cancelar',exact:true}).click();
  await page.locator('#client-actions').getByRole('button',{name:'Remover cliente',exact:true}).click();
  const removeClient=page.locator('#remove-client-dialog');
  assert.equal(await page.locator('#remove-client-name').textContent(),'Cliente automático');
  await removeClient.getByRole('button',{name:'Cancelar',exact:true}).click();assert.equal(removedClients,0);
  await page.locator('#client-actions').getByRole('button',{name:'Remover cliente',exact:true}).click();
  failClientDelete=true;await removeClient.getByRole('button',{name:'Remover cliente',exact:true}).click();
  await removeClient.locator('[data-form-error]').waitFor({state:'visible'});assert.equal(removedClients,0);
  assert.ok(state.sites.automatic);
  await removeClient.screenshot({path:path.join(root,'dist/remover-cliente.png')});
  failClientDelete=false;await removeClient.getByRole('button',{name:'Remover cliente',exact:true}).click();
  await page.locator('#overview').waitFor({state:'visible'});
  await page.waitForFunction(()=>document.querySelector('#site-count').textContent==='3');
  assert.equal(removedClients,1);
  assert.equal(await page.getByRole('link',{name:'Abrir cliente Cliente automático',exact:true}).count(),0);
  assert.equal(await page.getByRole('link',{name:'Abrir cliente Cliente Laboratório',exact:true}).count(),1);
  await page.getByRole('button',{name:'Minha conta',exact:true}).click();
  await page.locator('#change-password').click();
  const pf=page.locator('#password-form');await pf.locator('[name="current_password"]').fill('senha-atual-ficticia');await pf.locator('[name="new_password"]').fill('nova-senha-ficticia-123');await pf.locator('[name="confirm_password"]').fill('confirmacao-diferente');
  await pf.getByRole('button',{name:'Alterar senha',exact:true}).click();await pf.getByText('A confirmação não coincide com a nova senha.').waitFor();assert.equal(passwordBody,null);
  await pf.locator('[name="confirm_password"]').fill('nova-senha-ficticia-123');await pf.getByRole('button',{name:'Alterar senha',exact:true}).click();await page.locator('#password-done').waitFor();
  assert.equal(passwordBody.current_password,'senha-atual-ficticia');assert.equal(passwordBody.new_password,'nova-senha-ficticia-123');
  const before=stateGets;await page.waitForTimeout(5500);assert.equal(stateGets,before,'polling após troca de senha');assert.deepEqual(errors,[]);
  console.log(JSON.stringify({fixture:true,pfsenseRemovalAndReplacement:'passed',initialCommandAndCopy:'passed',newClientOpensInstallationCommand:'passed',singlePublicPortInstaller:'passed',agentVersionOSTooltip:'passed',clientRemovalCancellationErrorsAndSuccess:'passed',terminalServiceSelectionOnly:'passed',terminalHostnameAndLocalIP:'passed',authorizedServiceNamesOnly:'passed',automaticStatusPolling:'passed',offlineRed:'passed',serviceRemovalAndCancellation:'passed',endpointPencilEditAndErrors:'passed',oldHeaderButtonsRemoved:'passed',darkTheme:'passed',themePersistence:'passed',systemTheme:'passed',crossTabTheme:'passed',storageBlockedFallback:'passed',keyboardToggle:'passed',darkMobile320:'passed',backendPresence:'passed',clockIndependentStatus:'passed',staleCentralShowsUnknown:'passed',managementContactAndPendingPolicy:'passed',pfsenseCommandAndCopy:'passed',onlineInstallLink:'passed',reusableLinkServicesCopyRotationAndRevocation:'passed',linkSecretNotRetainedAfterReload:'passed',configuredListen:'passed',fourClientFields:'passed',singleServiceSelected:'passed',clientNavigation:'passed',terminalFiltering:'passed',automaticPort:'passed',serviceTypesAndWebLinks:'passed',selectedServices:'passed',passwordFlow:'passed',mobileOverflow:false,javascriptErrors:0}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(e=>{console.error(e);process.exit(1)});
