'use strict';
const form=document.querySelector('#first-access-form'),error=document.querySelector('#first-access-error');
form.addEventListener('submit',async event=>{
 event.preventDefault();const data=new FormData(form),button=form.querySelector('button');error.hidden=true;
 if(data.get('new_password')!==data.get('confirmation')){error.textContent='A confirmação não coincide com a nova senha.';error.hidden=false;return}
 button.disabled=true;
 try{
  const response=await fetch('/api/admin/account/password',{method:'POST',headers:{'Content-Type':'application/json','X-EdgeHub-Request':'1'},body:JSON.stringify({current_password:data.get('current_password'),new_password:data.get('new_password')})});
  if(response.status===401){window.location.replace('/login');return}
  if(!response.ok)throw new Error((await response.text()).trim());
  form.reset();window.location.replace('/login?password=changed');
 }catch(problem){error.textContent=problem instanceof TypeError?'Não foi possível acessar a central. Tente novamente.':problem.message;error.hidden=false}
 finally{button.disabled=false}
});
