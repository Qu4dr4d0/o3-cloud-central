'use strict';
const form=document.querySelector('#login-form'),error=document.querySelector('#login-error');
form.addEventListener('submit',async event=>{
 event.preventDefault();const fields=new FormData(form),button=form.querySelector('button[type="submit"]');
 error.hidden=true;button.disabled=true;button.textContent='Entrando…';
 try{
  const response=await fetch('/api/auth/login',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','X-EdgeHub-Request':'1'},body:JSON.stringify({username:fields.get('username'),password:fields.get('password')})});
  if(!response.ok)throw new Error((await response.text()).trim());
  const result=await response.json();form.reset();window.location.replace(result.must_change_password?'/first-access':'/');
 }catch(problem){
  error.textContent=problem instanceof TypeError?'Não foi possível acessar a central. Tente novamente.':problem.message;error.hidden=false;
  form.elements.password.value='';form.elements.password.focus();
 }finally{button.disabled=false;button.textContent='Entrar'}
});
