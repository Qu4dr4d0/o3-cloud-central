const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
(async()=>{
 const root=path.resolve(__dirname,'..'),password='fixture-password-123',accounts={admin:password};let username='';
 const server=http.createServer((req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  const json=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data))};
  if(req.method==='POST'){
   let raw='';req.on('data',chunk=>raw+=chunk);req.on('end',()=>{
    const body=JSON.parse(raw||'{}');
    if(req.url==='/api/auth/login'){
     if(accounts[body.username]!==body.password){res.writeHead(401);res.end('Usuário ou senha incorretos.');return}
     username=body.username;json({username});return;
    }
    if(req.url==='/api/auth/logout'){username='';json({ok:true});return}
    if(!username){res.writeHead(401);res.end('Entre novamente.');return}
    if(req.url==='/api/admin/users'){
     const name=body.username.toLowerCase();if(accounts[name]){res.writeHead(409);res.end('Este nome de usuário já está cadastrado.');return}
     accounts[name]=body.password;json({username:name});return;
    }
    res.writeHead(404);res.end();
   });return;
  }
  if(req.url==='/api/admin/state'){if(!username){res.writeHead(401);res.end();return}json({username,sites:{},devices:{},now:new Date().toISOString()});return}
  if(req.url==='/api/admin/users'){json({users:Object.keys(accounts).map(username=>({username}))});return}
  if(req.url==='/'&&!username){res.writeHead(303,{Location:'/login'});res.end();return}
  if(req.url==='/favicon.ico?v=6'){res.writeHead(200,{'Content-Type':'image/x-icon'});res.end(fs.readFileSync(path.join(root,'assets/O3CloudCentral.ico')));return}
  if(req.url==='/brand/logo.png'){res.writeHead(200,{'Content-Type':'image/png'});res.end(fs.readFileSync(path.join(root,'assets/O3CloudCentral.png')));return}
  const file={'/':'index.html','/login':'login.html','/app.js':'app.js','/login.js':'login.js','/theme.js':'theme.js','/style.css':'style.css'}[req.url];
  if(!file){res.writeHead(404);res.end();return}
  res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});res.end(fs.readFileSync(path.join(root,'web',file)));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1366,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  const origin='http://127.0.0.1:'+server.address().port;
  await page.goto(origin);await page.getByRole('heading',{name:'Entre na sua conta'}).waitFor();
  await page.locator('#login-form [name=username]').fill('admin');await page.locator('#login-form [name=password]').fill('incorrect');
  await page.getByRole('button',{name:'Entrar',exact:true}).click();await page.locator('#login-error').waitFor({state:'visible'});
  assert.equal(await page.locator('#login-form [name=password]').inputValue(),'');
  await page.screenshot({path:path.join(root,'dist/login-desktop.png')});
  await page.setViewportSize({width:320,height:740});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.locator('#theme-toggle').click();await page.screenshot({path:path.join(root,'dist/login-mobile-dark.png')});
  await page.setViewportSize({width:1366,height:900});await page.locator('#login-form [name=password]').fill(password);await page.getByRole('button',{name:'Entrar',exact:true}).click();
  await page.locator('#current-username').getByText('admin',{exact:true}).waitFor();
  await page.locator('#account-button').click();await page.locator('#manage-users').click();
  await page.locator('#users-list').getByText('admin',{exact:true}).waitFor();
  const form=page.locator('#user-form');await form.locator('[name=username]').fill('tecnico');await form.locator('[name=password]').fill(password);await form.locator('[name=confirm_password]').fill('mismatch-password');
  await form.getByRole('button',{name:'Criar usuário',exact:true}).click();await form.locator('[data-form-error]').waitFor({state:'visible'});
  assert.equal(accounts.tecnico,undefined);
  await form.locator('[name=confirm_password]').fill(password);await form.getByRole('button',{name:'Criar usuário',exact:true}).click();await page.locator('#user-created').waitFor({state:'visible'});
  await page.locator('#users-list').getByText('tecnico',{exact:true}).waitFor();
  assert.equal(await form.locator('[name=password]').inputValue(),'');assert.equal(await form.locator('[data-form-error]').isVisible(),false);
  await page.locator('#users-dialog').screenshot({path:path.join(root,'dist/usuarios-painel.png')});
  await form.getByRole('button',{name:'Fechar',exact:true}).click();await page.locator('#account-button').click();await page.locator('#logout').click();
  await page.getByRole('heading',{name:'Entre na sua conta'}).waitFor();
  await page.locator('#login-form [name=username]').fill('tecnico');await page.locator('#login-form [name=password]').fill(password);await page.getByRole('button',{name:'Entrar',exact:true}).click();
  await page.locator('#current-username').getByText('tecnico',{exact:true}).waitFor();
  await page.locator('#account-button').click();await page.keyboard.press('Escape');assert.equal(await page.locator('#account-menu').isVisible(),false);
  await page.locator('#account-button').click();await page.locator('#change-password').click();await page.locator('#account-username').getByText('tecnico',{exact:true}).waitFor();
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({loginErrors:true,loginRedirect:true,createUser:true,newUserLogin:true,correctUsername:true,logout:true,passwordsCleared:true,darkAndMobile:true,javascriptErrors:0}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(error=>{console.error(error);process.exitCode=1});
