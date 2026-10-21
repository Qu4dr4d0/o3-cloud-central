'use strict';
let state={sites:{},devices:{}},selectedID='',optionsSite='',passwordChanged=false,pendingWanted=false;
let snapshotFresh=false,snapshotReceivedAt=0,refreshPending=false,editingEndpointID='',removingClientID='',installingSiteID='',installLinkBusy=false;
let gatewayCommandBusy=false;
const $=s=>document.querySelector(s);
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}
function notify(text){$('#notice').textContent=text;$('#notice').hidden=false}
async function api(path,data,method='POST',binary=false){
 const ctl=path==='/state'&&method==='GET'?new AbortController():null;
 const timeout=ctl?setTimeout(()=>ctl.abort(),8000):null;
 try{
  const r=await fetch('/api/admin'+path,{method,cache:'no-store',signal:ctl?ctl.signal:undefined,headers:{'Content-Type':'application/json','X-O3CloudCentral-Request':'1'},body:data===undefined?undefined:JSON.stringify(data)});
  if(r.status===401){window.location.replace('/login');throw new Error('Sessão encerrada. Entre novamente.')}
  if(!r.ok)throw new Error((await r.text()).trim());return binary?await r.blob():await r.json();
 }finally{if(timeout)clearTimeout(timeout)}
}
function download(blob,name){const a=el('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function button(text,fn,cls='secondary'){const b=el('button',text,cls);b.type='button';b.addEventListener('click',async()=>{b.disabled=true;try{await fn();await refresh()}catch(e){notify(e.message)}finally{b.disabled=false}});return b}
function liveSnapshot(){return snapshotFresh&&performance.now()-snapshotReceivedAt<12000}
function badge(text,kind=''){return el('span',text,'badge '+kind)}
function installed(siteID){return Object.values(state.devices).filter(d=>!d.revoked&&d.public_key&&(!siteID||d.site_id===siteID))}
function active(d){return liveSnapshot()&&d.online===true}
function terminalState(d){return liveSnapshot()?(d.connection_state||(d.online?'online':'offline')):'unknown'}
function policySyncLabel(s){return !liveSnapshot()||s.policy_sync==='unknown'?'Configuração sem confirmação':s.policy_sync==='pending'?'Alterações pendentes no pfSense':s.policy_sync==='applied'?'Configuração aplicada':''}
function gatewayBadge(s){
 if(!liveSnapshot())return badge('Sem atualização','warn');
 const p=s.gateway_status||{state:'checking',online:false};
 const labels={online:'pfSense conectado',offline:'pfSense offline',checking:'Verificando pfSense',pending:'Aguardando pfSense',unknown:'Sem contato com pfSense'};
 const node=badge(labels[p.state]||'Estado não confirmado',p.state==='online'&&p.online?'good':p.state==='offline'?'bad':'warn');
 node.title=p.reason||'';if(s.last_source)node.title+=' Último contato recebido de '+s.last_source+'.';return node;
}
function emptyRow(body,text,columns){const tr=el('tr'),td=el('td',text,'empty-cell');td.colSpan=columns;tr.append(td);body.append(tr)}
function serviceType(s){
 if(s.type)return ['HTTP','HTTPS','SSH','TCP'].includes(s.type)?s.type:'TCP';
 return ({80:'HTTP',443:'HTTPS',22:'SSH'})[s.port]||'TCP';
}
function serviceAccess(s){
 const type=serviceType(s),address='127.0.0.1:'+s.local_port;
 return type==='HTTP'||type==='HTTPS'?type.toLowerCase()+'://'+address+'/':address;
}
function serviceAccessCell(s){
 const cell=el('td',undefined,'service-access'),address=serviceAccess(s);
 if(['HTTP','HTTPS'].includes(serviceType(s))){
  const link=el('a',address,'mono');link.href=address;link.target='_blank';link.rel='noopener noreferrer';link.setAttribute('aria-label',address+' — '+s.name+' (abre neste computador)');link.title='Requer o agente instalado e autorizado neste computador';cell.append(link);
 }else cell.append(el('span',address,'mono'));
 return cell;
}
function installationAddress(site){
 try{const u=new URL('https://'+site.endpoint);return u.origin}catch{return 'Endereço de instalação não definido'}
}
async function showGatewayCommand(site,reinstall=false){
 if(gatewayCommandBusy)throw new Error('Aguarde a geração do comando em andamento.');
 gatewayCommandBusy=true;
 try{
 const result=await api('/sites/'+encodeURIComponent(site.id)+(reinstall?'/reinstall-command':'/install-command'),{});
 if(selectedID!==site.id||!state.sites[site.id])throw new Error('O cliente selecionado mudou. Gere o comando novamente na tela desejada.');
 $('#gateway-install-title').textContent=reinstall?'Nova instalação no pfSense':'Instalar no pfSense';
 $('#gateway-install-description').textContent='Copie o comando e execute como root em Diagnostics → Command Prompt no pfSense deste cliente, ou no Shell do console.';
 $('#gateway-install-summary').textContent=reinstall?'Ao executar, o comando verifica o pacote, remove a instalação antiga deste cliente se existir e cria uma nova identidade do túnel. O cadastro do cliente, serviços e terminais são mantidos. Gerar o comando não interrompe a conexão atual.':'O comando baixa e verifica o pacote, cadastra este firewall e inicia o serviço. O comando contém um cadastro temporário.';
 const warning=$('#gateway-install-identity-warning');
 warning.hidden=!reinstall||!Object.values(state.devices).some(d=>d.site_id===site.id&&d.public_key&&!d.revoked);
 warning.textContent='A chave do pfSense será renovada. Os terminais já instalados precisarão ser reinstalados para reconhecer a nova chave; seus cadastros e permissões permanecem na central.';
 $('#gateway-install-command').value=result.command;
 $('#gateway-install-expiry').textContent='Válido até '+new Date(result.expires_at).toLocaleTimeString('pt-BR')+' · '+result.platform;
 $('#gateway-install-network').textContent='Instalação dos terminais: '+installationAddress(site)+' · Usa a mesma porta TCP do túnel.';
 $('#gateway-install-error').hidden=true;$('#copy-gateway-command').textContent='Copiar comando';openDialog('#gateway-install-dialog');
 }finally{gatewayCommandBusy=false;render()}
}
function terminalPlatform(){return $('#device-form').elements.platform.value}
function platformLink(site,platform=terminalPlatform()){return site.installation_links?.[platform]??(platform==='windows'?site.installation_link:null)}
function savePlatformLink(site,platform,link){site.installation_links={...(site.installation_links||{}),[platform]:link};if(platform==='windows')site.installation_link=link}
function showTerminalInstallLink(name,result,reusable=false,platform='windows'){
 $('#terminal-link-title').textContent=platform==='debian'?'Instalação Debian/Ubuntu':'Link de instalação';
 $('#terminal-install-name').textContent=name;
 $('#terminal-install-link').value=result.url;
 $('#terminal-install-command-box').hidden=!result.command;
 $('#terminal-install-command').value=result.command||'';
 $('#copy-terminal-command').hidden=!result.command;$('#copy-terminal-command').textContent='Copiar comando';
 $('#terminal-install-description').textContent=reusable?'Abra o mesmo link nas máquinas deste cliente para baixar e instalar o O3 Cloud Central.':'Abra este link na máquina do cliente para baixar e instalar o O3 Cloud Central. O link dá acesso somente ao cadastro deste terminal.';
 $('#terminal-install-expiry').textContent=reusable?'Válido até revogar · Várias máquinas':'Válido até '+new Date(result.expires_at).toLocaleString('pt-BR')+' · Uma máquina';
 $('#terminal-install-rules').textContent=reusable?'Cada máquina recebe seu próprio cadastro, com o hostname e os serviços escolhidos. Copie e guarde o link agora. Gerar um novo invalida o anterior para este sistema operacional; os terminais já instalados e o link do outro sistema continuam funcionando.':'Válido por 24 horas e para uma máquina. Gerar outro link ou instalador invalida o anterior. Cancelar o cadastro também cancela o link.';
 $('#copy-terminal-link').textContent='Copiar link';$('#terminal-link-error').hidden=true;openDialog('#terminal-link-dialog');
}
function installLinkServices(site,link){
 const ids=new Set(link.services||[]);
 return (site.services||[]).filter(service=>ids.has(service.id)).map(service=>service.name).join(', ')||'Nenhum serviço disponível';
}
function updateInstallLinkInfo(site){
 const link=platformLink(site),form=$('#device-form');
 form.elements.platform.disabled=installLinkBusy;
 $('#active-install-link').hidden=!link;
 $('#generate-client-link').textContent=link?'Gerar novo link':'Gerar link';
 $('#device-install-help').textContent=link?'Para usar o link atual, utilize a cópia que você guardou. Gerar um novo link substitui o anterior, sem afetar os terminais já instalados.':'Use o mesmo link em várias máquinas deste cliente. Cada terminal será cadastrado automaticamente com o hostname.';
 if(link){
  $('#active-install-link-services').textContent='Serviços: '+installLinkServices(site,link);
  const count=Number(link.installation_count)||0;
  $('#active-install-link-count').textContent=count+' '+(count===1?'instalação realizada':'instalações realizadas')+' · Válido até revogar';
 }
 form.querySelector('button[type="submit"]').disabled=installLinkBusy||!(site.services||[]).length;
 $('#revoke-client-link').disabled=installLinkBusy;
}
function openTerminalInstall(site){
 installingSiteID=site.id;$('#device-install-client').textContent='Cliente: '+site.name;
 renderServiceOptions(site);
 const link=platformLink(site),ids=new Set(link?.services||[]),services=site.services||[];
 const selected=!!link&&!services.every(service=>ids.has(service.id));
 const form=$('#device-form');form.elements.service_scope.value=selected?'selected':'all';
 $('#service-options').hidden=!selected;
 if(selected)$('#service-options').querySelectorAll('input').forEach(input=>input.checked=ids.has(input.value));
 updateInstallLinkInfo(site);openDialog('#device-dialog');
}
function render(){
 const username=state.username||'admin';$('#current-username').textContent=username;$('#account-username').textContent=username;
 const sites=Object.values(state.sites).sort((a,b)=>a.name.localeCompare(b.name)),all=installed();
 $('#updated').textContent=liveSnapshot()?'Dados da central: '+new Date(state.now).toLocaleTimeString('pt-BR'):'Sem atualização da central';
 $('#site-count').textContent=sites.length;$('#active-count').textContent=liveSnapshot()?all.filter(active).length:'—';$('#offline-count').textContent=liveSnapshot()?all.filter(d=>terminalState(d)==='offline').length:'—';
 const cards=$('#sites');cards.replaceChildren();
 if(!sites.length)cards.append(el('div','Cadastre o primeiro cliente para começar.','empty-state'));
 for(const s of sites){
  const card=el('a',undefined,'client-card');card.href='#cliente/'+encodeURIComponent(s.id);card.setAttribute('aria-label','Abrir cliente '+s.name);
  const head=el('div',undefined,'card-head');head.append(el('strong',s.name),gatewayBadge(s));card.append(head,el('div',s.endpoint,'endpoint'));
  const devices=installed(s.id),online=devices.filter(active).length;
  const offline=devices.filter(d=>terminalState(d)==='offline').length,unknown=devices.filter(d=>terminalState(d)==='unknown').length;
  card.append(el('div',(s.services||[]).length+' serviço(s) · '+(liveSnapshot()?online+' ativo(s) · '+offline+' offline'+(unknown?' · '+unknown+' sem confirmação':''):'estado sem atualização'),'card-summary'));
  const syncLabel=policySyncLabel(s);if(syncLabel)card.append(el('div',syncLabel,'helper'));
  card.append(el('span','Gerenciar cliente →','card-open'));cards.append(card);
 }
 const match=location.hash.match(/^#cliente\/(.+)$/);
 try{selectedID=match?decodeURIComponent(match[1]):''}catch{selectedID=''}
 const site=state.sites[selectedID];$('#overview').hidden=!!site;$('#client-view').hidden=!site;
 if(!site)return;
 $('#client-name').textContent=site.name;$('#client-status').replaceChildren(gatewayBadge(site));$('#client-endpoint').textContent=site.endpoint;$('#client-policy-status').textContent=policySyncLabel(site);
 document.querySelectorAll('[data-client-name]').forEach(n=>n.textContent='Cliente: '+site.name);
 const actions=$('#client-actions');actions.replaceChildren();
 const reinstallButton=button('Gerar nova instalação',async()=>{if(gatewayCommandBusy)return;try{await showGatewayCommand(site,true)}catch(error){notify(error.message)}},'secondary');
 reinstallButton.disabled=gatewayCommandBusy;actions.append(reinstallButton);
 actions.append(button('Remover cliente',()=>{removingClientID=site.id;$('#remove-client-name').textContent=site.name;openDialog('#remove-client-dialog')},'danger'));
 actions.hidden=!actions.childElementCount;
 const services=$('#services');services.replaceChildren();
 for(const svc of site.services||[]){
  const tr=el('tr'),availability=liveSnapshot()?svc.availability:'unverified',verified=['accessible','unavailable'].includes(availability);
  tr.append(el('td',svc.name),el('td',svc.target+':'+svc.port,'mono'),el('td',serviceType(svc)),serviceAccessCell(svc));
  const health=el('td');health.append(badge(verified?availability==='accessible'?'Acessível':'Indisponível':'Sem verificação',verified?availability==='accessible'?'good':'bad':''));tr.append(health);
  const actions=el('td'),remove=button('Remover',()=>removeService(site,svc),'danger');remove.setAttribute('aria-label','Remover serviço '+svc.name);actions.append(remove);tr.append(actions);services.append(tr);
 }
 if(!(site.services||[]).length)emptyRow(services,'Nenhum serviço cadastrado neste cliente.',6);
 const tbody=$('#devices');tbody.replaceChildren();
 for(const d of installed(site.id).sort((a,b)=>(a.hostname||a.name).localeCompare(b.hostname||b.name))){
  const tr=el('tr'),identity=el('td',undefined,'device-name');identity.append(el('div',d.hostname||'—'));
  if(d.name&&d.name!==d.hostname)identity.append(el('div',d.name,'device-label'));
  identity.title=[d.os,d.agent_version?'O3 Cloud Central '+d.agent_version:''].filter(Boolean).join(' · ');
  const address=el('td',d.local_ip||'—','mono');address.title='Último IP local informado pelo terminal';
  tr.append(identity,address,el('td',d.os==='windows'?'Windows':d.os==='linux'?'Linux':d.os||'—'));const status=el('td');status.append(badge(terminalState(d)==='online'?'Ativo':terminalState(d)==='offline'?'Offline':liveSnapshot()?'Sem confirmação':'Sem atualização',active(d)?'good':terminalState(d)==='offline'?'bad':'warn'));tr.append(status);
  const svc=el('td');for(const s of (site.services||[]).filter(s=>d.services.includes(s.id)))svc.append(el('div',s.name));if(!svc.childElementCount)svc.append(el('span','Nenhum','muted'));tr.append(svc);
  tr.append(el('td',new Date(d.last_seen).getFullYear()>2000?new Date(d.last_seen).toLocaleString('pt-BR'):'—'));
  const actions=el('td');if(d.os==='linux')actions.append(button('Comandos',()=>showLinuxCommands(d),'secondary'));
 actions.append(button('Remover acesso',()=>revoke(d),'danger'));tr.append(actions);tbody.append(tr);
 }
 if(!installed(site.id).length)emptyRow(tbody,'Nenhum terminal instalado com acesso autorizado.',7);
 const pending=Object.values(state.devices).filter(d=>d.site_id===site.id&&!d.revoked&&!d.public_key);
 $('#pending-details').hidden=!pending.length;$('#pending-title').textContent='Instalações pendentes ('+pending.length+')';
 if(pendingWanted&&pending.length){$('#pending-details').open=true;pendingWanted=false}
 const pendingBox=$('#pending-devices');pendingBox.replaceChildren();
 for(const d of pending){
  const row=el('div',undefined,'pending-row');row.append(el('strong',d.name));const actions=el('div',undefined,'actions');
  actions.append(button('Gerar link de instalação',async()=>{const result=await api('/devices/'+d.id+'/install-link',{});showTerminalInstallLink(d.name,result);}));
  actions.append(button('Gerar instalador',async()=>{download(await api('/devices/'+d.id+'/installer',{},'POST',true),'O3CloudCentral-setup.exe');notify('Instalador gerado. Execute em uma única máquina em até 15 minutos.');}));
  actions.append(button('Instalador Debian/Ubuntu',async()=>{download(await api('/devices/'+d.id+'/installer',{platform:'debian'},'POST',true),'O3CloudCentral-setup-debian.sh');notify('Instalador Debian/Ubuntu gerado. Execute como root em uma única máquina.');}));
  actions.append(button('Cancelar cadastro',()=>revoke(d),'danger'));row.append(actions);pendingBox.append(row);
 }
 const links=Object.values(site.installation_links||{windows:site.installation_link}).filter(Boolean),link=links[0],status=$('#client-install-link-status');
 status.hidden=!link;status.textContent=link?'Link de instalação ativo · '+links.reduce((total,item)=>total+(Number(item.installation_count)||0),0)+' instalações':'';
 $('#add-device').disabled=!(site.services||[]).length&&!link;
 if($('#device-dialog').open&&installingSiteID===site.id)updateInstallLinkInfo(site);
}
async function removeService(site,svc){
 if(!confirm('Remover o serviço '+svc.name+'? O acesso a ele será retirado de todos os terminais deste cliente.'))return;
 await api('/sites/'+encodeURIComponent(site.id)+'/services/'+encodeURIComponent(svc.id),undefined,'DELETE');
 notify('Serviço removido. A alteração será aplicada quando o pfSense sincronizar.');
}
async function revoke(d){if(confirm('Remover o acesso de '+d.name+'? O cadastro sairá da listagem.'))await api('/devices/'+d.id+'/revoke',{})}
function renderServiceOptions(site=state.sites[selectedID]){
 const box=$('#service-options'),old=new Set([...box.querySelectorAll('input:checked')].map(i=>i.value));
 if(!site)return;const preserve=optionsSite===site.id;optionsSite=site.id;box.replaceChildren();
 for(const s of site.services||[]){const label=el('label'),i=el('input');i.type='checkbox';i.name='service';i.value=s.id;i.checked=preserve&&old.has(s.id);label.append(i,document.createTextNode(s.name+' · '+serviceType(s)));box.append(label)}
 if(!(site.services||[]).length)box.append(el('span','Cadastre um serviço antes de adicionar terminais.'));
}
async function refresh(){if(passwordChanged||refreshPending)return;refreshPending=true;try{state=await api('/state',undefined,'GET');snapshotFresh=true;snapshotReceivedAt=performance.now();if($('#notice').textContent.startsWith('Sem atualização da central.'))$('#notice').hidden=true;render()}catch(e){snapshotFresh=false;render();notify('Sem atualização da central. Os estados não podem ser confirmados: '+e.message)}finally{refreshPending=false}}
function openDialog(id){const d=$(id),error=d.querySelector('[data-form-error]');if(error)error.hidden=true;d.showModal()}
function formError(form,text){const error=form.querySelector('[data-form-error]');error.textContent=text;error.hidden=!text}
function bindForm(id,fn){$(id).addEventListener('submit',async e=>{e.preventDefault();const form=e.target,b=form.querySelector('button[type="submit"]');b.disabled=true;form.querySelector('[data-form-error]').hidden=true;try{const message=await fn(new FormData(form));form.reset();form.closest('dialog').close();await refresh();notify(message||'Cadastro salvo.')}catch(err){formError(form,err.message)}finally{b.disabled=false}})}
$('#site-form').addEventListener('submit',async event=>{
 event.preventDefault();const form=event.target,submit=form.querySelector('button[type="submit"]'),data=new FormData(form);
 if(submit.disabled)return;submit.disabled=true;form.querySelector('[data-form-error]').hidden=true;
 try{
  const site=await api('/sites',{name:data.get('name'),endpoint:data.get('endpoint'),listen:data.get('listen'),cidrs:data.get('cidrs').split(',').map(value=>value.trim()).filter(Boolean)});
  state.sites[site.id]=site;history.replaceState(null,'','#cliente/'+encodeURIComponent(site.id));
  form.reset();$('#client-dialog').close();render();
  notify('Cliente cadastrado. Execute o comando no pfSense e adicione os serviços deste cliente.');
  try{await showGatewayCommand(site)}catch(error){notify('Cliente cadastrado. Não foi possível gerar o comando de instalação: '+error.message+'. Use “Gerar comando de instalação” para tentar novamente.')}
  await refresh();
 }catch(error){formError(form,error.message)}finally{submit.disabled=false}
});
bindForm('#remove-client-form',async()=>{
 const id=removingClientID;
 if(!id||!state.sites[id])throw new Error('O cliente não está mais disponível.');
 await api('/sites/'+encodeURIComponent(id),undefined,'DELETE');
 delete state.sites[id];
 for(const [key,device] of Object.entries(state.devices))if(device.site_id===id)delete state.devices[key];
 location.hash='#clientes';
 return 'Cliente removido.';
});
$('#remove-client-dialog').addEventListener('close',()=>{removingClientID='';$('#remove-client-name').textContent=''});
bindForm('#endpoint-form',async f=>{
 const id=editingEndpointID;
 if(!id||!state.sites[id])throw new Error('Selecione um cliente.');
 const endpoint=f.get('endpoint').trim();
 let hostnameChanged=false;try{hostnameChanged=new URL('https://'+endpoint).hostname!==new URL('https://'+state.sites[id].endpoint).hostname}catch{}
 const cidrs=f.get('cidrs').split(',').map(value=>value.trim()).filter(Boolean);
 await api('/sites/'+encodeURIComponent(id),{endpoint,cidrs},'PATCH');
 return hostnameChanged?'Cliente atualizado. Confira também o certificado do portal de instalação no pfSense para o novo DNS/IP.':'Cliente atualizado.';
});
bindForm('#service-form',async f=>{if(!state.sites[selectedID])throw new Error('Selecione um cliente.');const s=await api('/sites/'+selectedID+'/services',{name:f.get('name'),target:f.get('target'),port:Number(f.get('port')),protocol:'TCP',type:f.get('type')});return 'Serviço cadastrado. Acesso no terminal: '+serviceAccess(s);});
$('#device-form').addEventListener('submit',async event=>{
 event.preventDefault();if(installLinkBusy)return;
 const form=event.target,id=installingSiteID,site=state.sites[id],data=new FormData(form);
 form.querySelector('[data-form-error]').hidden=true;
 if(!site){formError(form,'O cliente não está mais disponível.');return}
 const available=new Set((site.services||[]).map(service=>service.id));
 const services=data.get('service_scope')==='all'?[...available]:data.getAll('service');
 if(!services.length){formError(form,'Selecione pelo menos um serviço permitido.');return}
 if(services.some(id=>!available.has(id))){formError(form,'Os serviços deste cliente mudaram. Feche e abra esta janela para escolher novamente.');return}
 const platform=data.get('platform');
 if(platformLink(site,platform)&&!confirm('Gerar um novo link para este sistema operacional? O link anterior deste sistema deixará de aceitar instalações. Os terminais já instalados e o link do outro sistema continuarão funcionando.'))return;
 installLinkBusy=true;updateInstallLinkInfo(site);
 try{
  const result=await api('/sites/'+encodeURIComponent(id)+'/install-link',{services,...(platform==='debian'?{platform}:{})});
  if(state.sites[id])savePlatformLink(state.sites[id],platform,{id:result.id,services:result.services,created_at:result.created_at,expires_at:result.expires_at,installation_count:result.installation_count});
  $('#device-dialog').close();showTerminalInstallLink('Cliente: '+site.name,result,true,platform);
  await refresh();
 }catch(error){formError(form,error.message)}finally{installLinkBusy=false;if(state.sites[id])updateInstallLinkInfo(state.sites[id])}
});
$('#device-form').elements.service_scope.forEach(input=>input.addEventListener('change',()=>{
 $('#service-options').hidden=$('#device-form').elements.service_scope.value!=='selected';
}));
$('#revoke-client-link').addEventListener('click',async()=>{
 if(installLinkBusy)return;
 const id=installingSiteID,site=state.sites[id],platform=terminalPlatform();if(!site||!platformLink(site,platform))return;
 if(!confirm('Revogar o link de instalação deste cliente? Ele deixará de aceitar novas instalações. Os terminais já instalados continuarão funcionando.'))return;
 installLinkBusy=true;updateInstallLinkInfo(site);
 try{
  await api('/sites/'+encodeURIComponent(id)+'/install-link',platform==='debian'?{platform}:{},'DELETE');
  if(state.sites[id])savePlatformLink(state.sites[id],platform,null);
  updateInstallLinkInfo(site);await refresh();notify('Link revogado. Os terminais já instalados continuam funcionando.');
 }catch(error){formError($('#device-form'),error.message)}finally{installLinkBusy=false;if(state.sites[id])updateInstallLinkInfo(state.sites[id])}
});
$('#device-dialog').addEventListener('close',()=>{installingSiteID=''});
$('#device-form').elements.platform.addEventListener('change',()=>{
 const site=state.sites[installingSiteID];if(site)openTerminalInstall(site);
});

$('#password-form').addEventListener('submit',async e=>{
 e.preventDefault();const form=e.target,f=new FormData(form),b=form.querySelector('button[type="submit"]');form.querySelector('[data-form-error]').hidden=true;
 if(f.get('new_password')!==f.get('confirm_password')){formError(form,'A confirmação não coincide com a nova senha.');return}
 b.disabled=true;try{await api('/account/password',{current_password:f.get('current_password'),new_password:f.get('new_password')});passwordChanged=true;clearInterval(refreshTimer);form.reset();form.hidden=true;$('#password-done').hidden=false;$('#reauth').hidden=false;}catch(err){formError(form,err.message)}finally{b.disabled=false}
});
$('#add-client').addEventListener('click',()=>openDialog('#client-dialog'));
const presetPorts={HTTP:'80',HTTPS:'443',SSH:'22',TCP:''};
let lastPresetPort='80';
const typeHints={HTTP:'Página web HTTP. O endereço local será definido automaticamente.',HTTPS:'Página web com TLS. O certificado do site precisa corresponder ao endereço usado no navegador.',SSH:'Acesso SSH ao servidor de destino. Use as credenciais desse servidor no seu cliente SSH.',TCP:'Use para bancos de dados e outros serviços TCP. Informe a porta real do servidor.'};
function updateServiceType(){
 const form=$('#service-form'),type=form.elements.type.value,port=form.elements.port;
 if(!port.value||port.value===lastPresetPort)port.value=presetPorts[type];
 lastPresetPort=presetPorts[type];$('#service-type-hint').textContent=typeHints[type];
}
$('#service-form select[name="type"]').addEventListener('change',updateServiceType);
$('#add-service').addEventListener('click',()=>{lastPresetPort=presetPorts[$('#service-form').elements.type.value];updateServiceType();openDialog('#service-dialog')});
$('#add-device').addEventListener('click',()=>{const site=state.sites[selectedID];if(site)openTerminalInstall(site)});
$('#edit-endpoint').addEventListener('click',()=>{
 const site=state.sites[selectedID];if(!site)return;
 editingEndpointID=site.id;const form=$('#endpoint-form');form.elements.endpoint.value=site.endpoint;form.elements.cidrs.value=(site.cidrs||[]).join(', ');openDialog('#endpoint-dialog');
});
$('#endpoint-dialog').addEventListener('close',()=>{editingEndpointID='';$('#endpoint-form').reset()});
function closeAccountMenu(){$('#account-menu').hidden=true;$('#account-button').setAttribute('aria-expanded','false')}
$('#account-button').addEventListener('click',()=>{const open=$('#account-menu').hidden;$('#account-menu').hidden=!open;$('#account-button').setAttribute('aria-expanded',String(open))});
$('#change-password').addEventListener('click',()=>{closeAccountMenu();openDialog('#account-dialog')});
async function loadUsers(){const data=await api('/users',undefined,'GET');const list=$('#users-list');list.replaceChildren();for(const user of data.users){list.append(el('span',user.username,'badge'))}}
$('#manage-users').addEventListener('click',async()=>{closeAccountMenu();$('#user-created').hidden=true;openDialog('#users-dialog');try{await loadUsers()}catch(error){formError($('#user-form'),error.message)}});
$('#user-form').addEventListener('submit',async event=>{
 event.preventDefault();const form=event.currentTarget,fields=new FormData(form),submit=form.querySelector('[type="submit"]');
 $('#user-created').hidden=true;
 if(fields.get('password')!==fields.get('confirm_password')){formError(form,'A confirmação não coincide com a senha.');return}
 submit.disabled=true;try{const result=await api('/users',{username:fields.get('username'),password:fields.get('password')});form.reset();formError(form,'');$('#user-created').textContent='Usuário '+result.username+' criado.';$('#user-created').hidden=false;await loadUsers()}catch(error){formError(form,error.message)}finally{submit.disabled=false}
});
$('#users-dialog').addEventListener('close',()=>{$('#user-form').reset();$('#user-created').hidden=true;formError($('#user-form'),'')});
$('#logout').addEventListener('click',async()=>{
 const button=$('#logout');button.disabled=true;
 try{const response=await fetch('/api/auth/logout',{method:'POST',headers:{'Content-Type':'application/json','X-O3CloudCentral-Request':'1'},body:'{}'});if(!response.ok&&response.status!==401)throw new Error('Não foi possível sair. Tente novamente.');passwordChanged=true;clearInterval(refreshTimer);window.location.replace('/login')}catch(error){notify(error.message)}finally{button.disabled=false}
});
document.addEventListener('click',event=>{if(!event.target.closest('#account-button')&&!event.target.closest('#account-menu'))closeAccountMenu()});
document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!$('#account-menu').hidden){closeAccountMenu();$('#account-button').focus()}});
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.closest('dialog').close()));
$('#account-dialog').addEventListener('close',()=>$('#password-form').reset());
window.addEventListener('hashchange',()=>{document.querySelectorAll('dialog[open]').forEach(d=>d.close());render()});
refresh();const refreshTimer=setInterval(refresh,5000);
setInterval(()=>{if(!passwordChanged&&snapshotFresh&&!liveSnapshot()){snapshotFresh=false;render();notify('Sem atualização da central. Aguardando uma nova leitura dos estados.')}},1000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!passwordChanged)refresh()});

$('#copy-gateway-command').addEventListener('click',async()=>{
 const field=$('#gateway-install-command');
 try{await navigator.clipboard.writeText(field.value);$('#copy-gateway-command').textContent='Copiado';}
 catch{field.focus();field.select();$('#gateway-install-error').textContent='O navegador não liberou a cópia. O comando foi selecionado: pressione Ctrl + C.';$('#gateway-install-error').hidden=false;}
});
$('#gateway-install-dialog').addEventListener('close',()=>{$('#gateway-install-command').value=''});

$('#copy-terminal-link').addEventListener('click',async()=>{
 const field=$('#terminal-install-link');
 try{await navigator.clipboard.writeText(field.value);$('#copy-terminal-link').textContent='Copiado';}
 catch{field.focus();field.select();$('#terminal-link-error').textContent='Link selecionado: pressione Ctrl + C.';$('#terminal-link-error').hidden=false;}
});
$('#copy-terminal-command').addEventListener('click',async()=>{
 const field=$('#terminal-install-command');
 try{await navigator.clipboard.writeText(field.value);$('#copy-terminal-command').textContent='Comando copiado'}
 catch{field.focus();field.select();$('#terminal-link-error').textContent='Comando selecionado: pressione Ctrl + C.';$('#terminal-link-error').hidden=false}
});
$('#terminal-link-dialog').addEventListener('close',()=>{$('#terminal-install-link').value='';$('#terminal-install-command').value=''});

function showLinuxCommands(device){
 $('#linux-commands-host').textContent=device.hostname||device.name||'Terminal Linux';
 const list=$('#linux-command-list');list.replaceChildren();
 for(const [action,label] of [['status','Ver estado'],['start','Conectar'],['stop','Parar'],['restart','Reconectar'],['log','Ver logs'],['uninstall','Desinstalar'],['help','Ver ajuda']]){
  const row=el('div',undefined,'linux-command-row'),field=document.createElement('input');
  field.value='sudo o3cloudcentral-agent '+action;field.readOnly=true;field.setAttribute('aria-label',label);
  row.append(el('strong',label),field,button('Copiar',async()=>{try{await navigator.clipboard.writeText(field.value);notify('Comando copiado')}catch{field.focus();field.select();notify('Comando selecionado: pressione Ctrl + C.')}},'secondary'));list.append(row);
 }
 openDialog('#linux-commands-dialog');
}
