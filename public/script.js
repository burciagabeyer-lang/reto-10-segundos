!function(){
  var API = '/api/v1-secure-engine-x92';
  var state = { phase: 'idle', token: null, t0: null, iv: null, autoStop: null, keys: [] };
  var admKey = '';
  var $ = function(s){ return document.querySelector(s); };

  function toast(msg){
    var t = $('#toast'); t.textContent = msg; t.classList.add('vis');
    setTimeout(function(){ t.classList.remove('vis'); }, 3000);
  }

  function fmt(ms){
    var s = Math.max(0, ms);
    var secs = Math.floor(s / 1000);
    var cents = Math.floor((s % 1000) / 10);
    return secs.toString().padStart(2,'0') + '.' + cents.toString().padStart(2,'0');
  }

  function call(action, method, body, extra){
    return fetch(API + '?action=' + action + (extra||''), {
      method: method || 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : null
    }).then(function(r){
      return r.json().then(function(d){ if (!r.ok) throw new Error(d.error || 'Error'); return d; });
    });
  }

  window.handleBtn = function(evt){
    if (state.phase === 'idle'){
      var key = $('#playerKey').value.trim();
      if (!key) return toast('Ingresa tu clave');
      $('#btn').disabled = true;
      
      call('start','POST',{ key: key }).then(function(d){
          state.token = d.token; state.t0 = performance.now(); state.phase = 'running';
          $('#btn').disabled = false; $('#btn').textContent = '¡DETENER!'; $('#btn').classList.add('run');
          $('#tmr').classList.add('run');
          $('#inputArea').style.display = 'none';
          
          state.iv = setInterval(function(){
            if (state.phase === 'running') $('#tmr').textContent = fmt(performance.now() - state.t0);
          }, 16);
          window.updateRing(); // Inicia animación del anillo en el HTML

          state.autoStop = setTimeout(function(){ if (state.phase === 'running') doStop(false, true); }, 14500);
      }).catch(function(e){ toast(e.message); $('#btn').disabled = false; });

    } else if (state.phase === 'running'){
      if (performance.now() - state.t0 < 3000) return toast('Espera 3 segundos...');
      doStop(evt ? evt.isTrusted : false, false);
    }
  };

  function doStop(trusted, isAuto){
    state.phase = 'stopped';
    clearInterval(state.iv); clearTimeout(state.autoStop);
    var elapsed = Math.round(performance.now() - state.t0);
    $('#btn').disabled = true;
    $('#btn').textContent = 'VERIFICANDO...';

    call('stop','POST',{ token: state.token, isTrusted: trusted === true, clientElapsed: elapsed })
    .then(function(d){
      $('#tmr').textContent = fmt(d.serverElapsed);
      $('#tmr').classList.remove('run');
      if(d.isWinner) $('#tmr').classList.add('win'); else $('#tmr').classList.add('lose');
      
      // Llamamos a la función visual del HTML
      window.showFinalResult(d.isWinner, fmt(d.serverElapsed));
      state.phase = 'idle';
    })
    .catch(function(e){ toast(e.message); location.reload(); });
  }

  // Admin & Otros
  window.navTo = function(s){
    document.querySelectorAll('.scr').forEach(x=>x.classList.remove('on'));
    if(s==='game'){$('#gameScr').classList.add('on');$('#nGame').classList.add('act')}
    else{$('#admScr').classList.add('on');$('#nAdmin').classList.add('act')}
  };

  window.admAuth = function(){
    admKey = $('#admKey').value;
    call('audit','GET',null,'&key='+encodeURIComponent(admKey)).then(d=>{
      $('#admLogin').style.display='none'; $('#admBody').style.display='block';
      $('#admTb').innerHTML = d.entries.map(e=>`<tr><td>${e.playerKey}</td><td>${(e.serverElapsed/1000).toFixed(2)}s</td><td>${e.status}</td></tr>`).join('');
    }).catch(e=>toast(e.message));
  };

  call('ping').then(()=>{$('#calScr').classList.remove('on');$('#gameScr').classList.add('on')});
}();
