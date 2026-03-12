!function(){
  var API = '/api/v1-secure-engine-x92';
  var state = {
    phase: 'idle',
    token: null,
    t0: null,
    iv: null,
    autoStop: null,
    keys: []
  };
  var admKey = '';
  var $ = function(s){ return document.querySelector(s); };

  function toast(msg){
    var t = $('#toast');
    t.textContent = msg;
    t.classList.add('vis');
    setTimeout(function(){ t.classList.remove('vis'); }, 3500);
  }

  // ══════════════════════════════════════
  // FORMAT: 2 decimals — XX.XX
  // ══════════════════════════════════════
  function fmt(ms){
    var s = Math.max(0, ms);
    var secs = Math.floor(s / 1000);
    var cents = Math.floor((s % 1000) / 10); // centiseconds (2 digits)
    return secs.toString().padStart(2,'0') + '.' + cents.toString().padStart(2,'0');
  }

  function call(action, method, body, extra){
    return fetch(API + '?action=' + action + (extra||''), {
      method: method || 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : null
    }).then(function(r){
      return r.json().then(function(d){
        if (!r.ok) throw new Error(d.error || 'Error');
        return d;
      });
    });
  }

  // Anti-tamper
  document.addEventListener('contextmenu', function(e){ e.preventDefault(); });
  document.onkeydown = function(e){
    if (e.keyCode===123 || (e.ctrlKey&&e.shiftKey&&(e.keyCode===73||e.keyCode===74)) || (e.ctrlKey&&e.keyCode===85)) return false;
  };
  document.addEventListener('keydown', function(e){
    if (e.code==='Space' && !e.repeat && $('#gameScr').classList.contains('on')){
      e.preventDefault();
      var b = $('#btn');
      if (!b.disabled) handleBtn(e);
    }
  });

  // Nav
  window.navTo = function(scr){
    document.querySelectorAll('.scr').forEach(function(s){ s.classList.remove('on'); });
    document.querySelectorAll('.nav-b').forEach(function(b){ b.classList.remove('act'); });
    if (scr==='game'){ $('#gameScr').classList.add('on'); $('#nGame').classList.add('act'); }
    else { $('#admScr').classList.add('on'); $('#nAdmin').classList.add('act'); }
  };

  // ═══════════════════════════════════════════════════════════
  // GAME
  // ═══════════════════════════════════════════════════════════
  window.handleBtn = function handleBtn(evt){
    if (state.phase === 'idle'){
      var key = $('#playerKey').value.trim();
      if (!key) return toast('Ingresa tu clave de acceso');
      $('#btn').disabled = true;
      $('#btn').textContent = 'VALIDANDO...';

      call('start','POST',{ key: key })
        .then(function(d){
          state.token = d.token;
          state.t0 = performance.now();
          state.phase = 'running';
          $('#btn').disabled = false;
          $('#btn').textContent = '¡DETENER!';
          $('#btn').classList.add('run');
          $('#tmr').classList.add('run');
          $('#tmr').classList.remove('win','lose');
          $('#playerKey').style.display = 'none';
          
          // Timer visual
          state.iv = setInterval(function(){
            if (state.phase !== 'running') return;
            $('#tmr').textContent = fmt(performance.now() - state.t0);
          }, 16);
          
          // Auto-stop 14.5s
          state.autoStop = setTimeout(function(){
            if (state.phase === 'running') doStop(false, true);
          }, 14500);
        })
        .catch(function(e){
          toast(e.message);
          $('#btn').disabled = false;
          $('#btn').textContent = 'INICIAR RETO';
        });

    } else if (state.phase === 'running'){
      // Cooldown de 3 segundos para evitar clics accidentales
      if (performance.now() - state.t0 < 3000) return toast('Espera un poco más...');
      doStop(evt ? evt.isTrusted : false, false);
    }
  };

  function doStop(trusted, isAuto){
    if (state.phase !== 'running') return;
    state.phase = 'stopped';
    if (state.iv){ clearInterval(state.iv); state.iv = null; }
    if (state.autoStop){ clearTimeout(state.autoStop); state.autoStop = null; }
    
    var elapsed = Math.round(performance.now() - state.t0);
    $('#btn').disabled = true;
    $('#btn').textContent = isAuto ? '⏰ TIEMPO AGOTADO' : 'VERIFICANDO...';

    call('stop','POST',{
      token: state.token,
      isTrusted: isAuto ? false : (trusted === true),
      clientElapsed: elapsed
    })
    .then(function(d){
      // Actualizamos con el tiempo exacto del servidor (2 decimales)
      $('#tmr').textContent = fmt(d.serverElapsed);
      showResult(d, isAuto);
    })
    .catch(function(e){
      toast(e.message);
      showResult({
        serverElapsed: elapsed,
        diff: Math.abs(elapsed - 10000),
        isWinner: false,
        status: 'ERROR'
      }, isAuto);
    });
  }

  function showResult(d, wasAuto){
    var tmr = $('#tmr');
    var btn = $('#btn');
    tmr.classList.remove('run');

    // La lógica de clase 'win' o 'lose' ahora depende de lo que diga el servidor
    // según la tolerancia de 1 segundo (1000ms) que configuramos en la API.
    if (d.isWinner){
      tmr.classList.add('win');
    } else {
      tmr.classList.add('lose');
    }

    // Reset de estado
    state.token = null;
    state.phase = 'idle';
    btn.classList.remove('run');
    btn.textContent = 'JUGAR DE NUEVO';
    btn.disabled = false;
    
    btn.onclick = function(){
      tmr.textContent = '00.00';
      tmr.classList.remove('run','win','lose');
      $('#playerKey').style.display = 'block';
      $('#playerKey').value = '';
      btn.textContent = 'INICIAR RETO';
      btn.classList.remove('run');
      btn.onclick = null;
    };
  }

  // Protección antes de cerrar la pestaña
  window.addEventListener('beforeunload', function(){
    if (state.phase === 'running' && state.token){
      navigator.sendBeacon(
        API + '?action=stop',
        new Blob([JSON.stringify({
          token: state.token,
          isTrusted: false,
          clientElapsed: Math.round(performance.now() - state.t0)
        })], { type: 'application/json' })
      );
    }
  });

  // ═══════════════════════════════════════════════════════════
  // ADMIN FUNCTIONS
  // ═══════════════════════════════════════════════════════════
  window.admAuth = function(){
    admKey = $('#admKey').value.trim();
    if (!admKey) return toast('Ingresa la clave de admin');
    call('audit','GET',null,'&key='+encodeURIComponent(admKey))
      .then(function(d){
        $('#admLogin').style.display = 'none';
        $('#admBody').style.display = 'block';
        renderAudit(d.entries || []);
      })
      .catch(function(e){ toast(e.message); });
  };

  function renderAudit(entries){
    var tb = $('#admTb');
    if (!entries.length){ 
        tb.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--dim,#888)">Sin registros</td></tr>'; 
        return; 
    }
    tb.innerHTML = entries.map(function(e){
      var time = e.serverElapsed ? (e.serverElapsed/1000).toFixed(3)+'s' : '—';
      var diff = e.diff !== undefined ? e.diff+'ms' : '—';
      var c = {
          'GANADOR':'var(--green,#22c55e)',
          'GANADOR_PENDIENTE':'var(--green,#22c55e)',
          'REVISION_MANUAL':'var(--amber,#f59e0b)',
          'SOSPECHOSO':'var(--red,#ef4444)',
          'EXPIRADO':'var(--red,#ef4444)',
          'LIMPIO':'var(--text-3,#888)'
      }[e.status] || 'var(--text-3,#888)';
      
      var k = e.playerKey ? e.playerKey.slice(0,6)+'..' : '—';
      var fl = e.flags && e.flags.length ? ' ⚠' : '';
      return '<tr><td>'+k+'</td><td>'+time+'</td><td>'+diff+'</td><td style="color:'+c+';font-weight:bold">'+e.status+fl+'</td></tr>';
    }).join('');
  }

  window.generateKeys = function(){
    var n = $('#genCount').value || 10;
    call('gen','GET',null,'&key='+encodeURIComponent(admKey)+'&count='+n)
      .then(function(d){
        state.keys = d.keys || [];
        $('#btnDl').style.display = 'block';
        toast('✅ '+state.keys.length+' claves generadas');
        call('audit','GET',null,'&key='+encodeURIComponent(admKey)).then(function(d){ renderAudit(d.entries||[]); });
      })
      .catch(function(e){ toast(e.message); });
  };

  window.downloadKeys = function(){
    if (!state.keys.length) return toast('No hay claves');
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([state.keys.join('\n')],{type:'text/plain'}));
    a.download = 'claves_'+new Date().toISOString().slice(0,10)+'.txt';
    a.click();
  };

  // Ping inicial
  call('ping').then(function(){
    $('#calScr').classList.remove('on');
    $('#gameScr').classList.add('on');
  }).catch(function(){
    $('#calDet').textContent = 'Error al conectar. Recarga la página.';
  });
}();
