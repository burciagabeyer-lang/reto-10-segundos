!function(){
  var API = '/api/v1-secure-engine-x92';
  var state = { phase:'idle', token:null, t0:null, iv:null, autoStop:null, keys:[] };
  var admKey = '';
  var $ = function(s){ return document.querySelector(s); };

  function toast(msg){
    var t=$('#toast');t.textContent=msg;t.classList.add('vis');
    setTimeout(function(){t.classList.remove('vis')},3500);
  }

  function fmt(ms){
    var s=Math.max(0,ms);
    return Math.floor(s/1000).toString().padStart(2,'0')+'.'+Math.floor((s%1000)/10).toString().padStart(2,'0');
  }

  function call(action,method,body,extra){
    return fetch(API+'?action='+action+(extra||''),{
      method:method||'GET',headers:{'Content-Type':'application/json'},
      body:body?JSON.stringify(body):null
    }).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||'Error');return d})});
  }

  document.addEventListener('contextmenu',function(e){e.preventDefault()});
  document.onkeydown=function(e){if(e.keyCode===123||(e.ctrlKey&&e.shiftKey&&(e.keyCode===73||e.keyCode===74))||(e.ctrlKey&&e.keyCode===85))return false};
  document.addEventListener('keydown',function(e){if(e.code==='Space'&&!e.repeat&&$('#gameScr').classList.contains('on')){e.preventDefault();var b=$('#btn');if(!b.disabled)handleBtn(e)}});

  window.navTo=function(scr){
    document.querySelectorAll('.scr').forEach(function(s){s.classList.remove('on')});
    document.querySelectorAll('.nav-b').forEach(function(b){b.classList.remove('act')});
    if(scr==='game'){$('#gameScr').classList.add('on');$('#nGame').classList.add('act')}
    else{$('#admScr').classList.add('on');$('#nAdmin').classList.add('act')}
  };

  window.handleBtn=function handleBtn(evt){
    if(state.phase==='idle'){
      var key=$('#playerKey').value.trim();
      if(!key)return toast('Ingresa tu clave de acceso');
      $('#btn').disabled=true;$('#btn').textContent='VALIDANDO...';
      call('start','POST',{key:key})
        .then(function(d){
          state.token=d.token;state.t0=performance.now();state.phase='running';
          $('#btn').disabled=false;$('#btn').textContent='¡DETENER!';$('#btn').classList.add('run');
          var t=$('#tmr');t.classList.add('run');t.classList.remove('win','lose');
          t.removeAttribute('data-diff');t.removeAttribute('data-winner');t.removeAttribute('data-status');t.removeAttribute('data-elapsed');t.removeAttribute('data-auto');
          $('#playerKey').style.display='none';
          state.iv=setInterval(function(){if(state.phase!=='running')return;$('#tmr').textContent=fmt(performance.now()-state.t0)},16);
          state.autoStop=setTimeout(function(){if(state.phase==='running')doStop(false,true)},14500);
        })
        .catch(function(e){toast(e.message);$('#btn').disabled=false;$('#btn').textContent='INICIAR RETO'});
    }else if(state.phase==='running'){
      if(performance.now()-state.t0<3000)return toast('Espera un poco más...');
      doStop(evt?evt.isTrusted:false,false);
    }
  };

  function doStop(trusted,isAuto){
    if(state.phase!=='running')return;state.phase='stopped';
    if(state.iv){clearInterval(state.iv);state.iv=null}
    if(state.autoStop){clearTimeout(state.autoStop);state.autoStop=null}
    var elapsed=Math.round(performance.now()-state.t0);
    $('#btn').disabled=true;$('#btn').textContent=isAuto?'⏰ TIEMPO AGOTADO':'VERIFICANDO...';

    call('stop','POST',{token:state.token,isTrusted:isAuto?false:(trusted===true),clientElapsed:elapsed})
    .then(function(d){finish(d,isAuto)})
    .catch(function(e){toast(e.message);finish({serverElapsed:elapsed,diff:Math.abs(elapsed-10000),isWinner:false,status:'ERROR'},isAuto)});
  }

  function finish(d,wasAuto){
    var t=$('#tmr'),b=$('#btn');
    t.textContent=fmt(d.serverElapsed);
    t.dataset.diff=d.diff;t.dataset.winner=d.isWinner?'true':'false';
    t.dataset.status=d.status||'';t.dataset.elapsed=d.serverElapsed;t.dataset.auto=wasAuto?'true':'false';
    t.classList.remove('run');
    t.classList.add(d.isWinner?'win':'lose');
    state.token=null;state.phase='idle';
    b.classList.remove('run');b.textContent='JUGAR DE NUEVO';b.disabled=false;
    b.onclick=function(){
      t.textContent='00.00';t.classList.remove('run','win','lose');
      t.removeAttribute('data-diff');t.removeAttribute('data-winner');t.removeAttribute('data-status');t.removeAttribute('data-elapsed');t.removeAttribute('data-auto');
      $('#playerKey').style.display='block';$('#playerKey').value='';
      b.textContent='INICIAR RETO';b.classList.remove('run');b.onclick=null;
    };
  }

  window.addEventListener('beforeunload',function(){
    if(state.phase==='running'&&state.token){
      navigator.sendBeacon(API+'?action=stop',new Blob([JSON.stringify({token:state.token,isTrusted:false,clientElapsed:Math.round(performance.now()-state.t0)})],{type:'application/json'}));
    }
  });

  window.admAuth=function(){
    admKey=$('#admKey').value.trim();if(!admKey)return toast('Ingresa la clave de admin');
    call('audit','GET',null,'&key='+encodeURIComponent(admKey))
    .then(function(d){$('#admLogin').style.display='none';$('#admBody').style.display='block';renderAudit(d.entries||[])})
    .catch(function(e){toast(e.message)});
  };
  function renderAudit(entries){
    var tb=$('#admTb');
    if(!entries.length){tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:#888">Sin registros</td></tr>';return}
    tb.innerHTML=entries.map(function(e){
      var time=e.serverElapsed?(e.serverElapsed/1000).toFixed(3)+'s':'—';
      var diff=e.diff!==undefined?e.diff+'ms':'—';
      var c={'GANADOR_PENDIENTE':'#22c55e','REVISION_MANUAL':'#f59e0b','SOSPECHOSO':'#ef4444','EXPIRADO':'#ef4444','REPLAY_DETECTADO':'#ef4444','LIMPIO':'#888'}[e.status]||'#888';
      var k=e.playerKey?e.playerKey.slice(0,6)+'..':'—';var fl=e.flags&&e.flags.length?' ⚠':'';
      return '<tr><td>'+k+'</td><td>'+time+'</td><td>'+diff+'</td><td style="color:'+c+';font-weight:bold">'+e.status+fl+'</td></tr>';
    }).join('');
  }
  window.generateKeys=function(){
    var n=$('#genCount').value||10;
    call('gen','GET',null,'&key='+encodeURIComponent(admKey)+'&count='+n)
    .then(function(d){state.keys=d.keys||[];$('#btnDl').style.display='block';toast('✅ '+state.keys.length+' claves generadas');
      call('audit','GET',null,'&key='+encodeURIComponent(admKey)).then(function(d){renderAudit(d.entries||[])})
    }).catch(function(e){toast(e.message)});
  };
  window.downloadKeys=function(){
    if(!state.keys.length)return toast('No hay claves');
    var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([state.keys.join('\n')],{type:'text/plain'}));
    a.download='claves_'+new Date().toISOString().slice(0,10)+'.txt';a.click();
  };

  call('ping').then(function(){$('#calScr').classList.remove('on');$('#gameScr').classList.add('on')})
  .catch(function(){$('#calDet').textContent='Error al conectar. Recarga la página.'});
}();
