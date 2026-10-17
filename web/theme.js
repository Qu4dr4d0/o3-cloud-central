'use strict';
(()=>{
 const key='o3cloudcentral-theme',root=document.documentElement;
 const system=window.matchMedia('(prefers-color-scheme: dark)');
 const valid=value=>value==='dark'||value==='light';
 let preference=null;
 try{const saved=localStorage.getItem(key);if(valid(saved))preference=saved}catch{}
 function apply(){
  const dark=preference?preference==='dark':system.matches;
  root.dataset.theme=dark?'dark':'light';
  const button=document.getElementById('theme-toggle');
  if(button){button.setAttribute('aria-pressed',String(dark));button.title=dark?'Ativar modo claro':'Ativar modo escuro'}
 }
 apply();
 document.addEventListener('DOMContentLoaded',()=>{
  apply();
  document.getElementById('theme-toggle').addEventListener('click',()=>{
   preference=root.dataset.theme==='dark'?'light':'dark';
   try{localStorage.setItem(key,preference)}catch{}
   apply();
  });
 });
 system.addEventListener('change',()=>{if(!preference)apply()});
 window.addEventListener('storage',event=>{
  if(event.key===key||event.key===null){preference=valid(event.newValue)?event.newValue:null;apply()}
 });
})();
