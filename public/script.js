 <script>
  (function(){
    var API='/api/game';
    var S={phase:'idle',token:null,t0:null,lat:0,iv:null,hist:[]};
    var $=function(s){return document.querySelector(s)};
    var tmr=$('#tmr'),btn=$('#btn');

    function toast(m,d){d=d||3000;var t=$('#toast');t.textContent=m;t.classList.add('vis');setTimeout(function(){t.classList.remove('vis')},d)}
    function fmt(ms){var s=Math.floor(ms/1000).toString();while(s.length<2)s='0'+s;var m=Math.floor(ms%1000).toString();while(m.length<3)m='0'+m;return s+'.'+m}

    function api(act,method,body,p){
      method=method||'GET';p=p||'';
      var u=API+'?action='+act+p;
      var o={method:method,headers:{'Content-Type':'application/json'}};
      if(body)o.body=JSON.stringify(body);
      return fetch(u,o).then(function(r){
        return r.json().then(function(d){
          if(!r.ok)throw new Error(d.error||'Error del servidor');
          return d;
        });
      });
    }

    function navTo(n){
      document.querySelectorAll('.scr').forEach(function(s){s.classList.remove('on')});
      document.querySelectorAll('.nav-b').forEach(function(b){b.classList.remove('act')});
      if(n==='game'){
        (S.phase==='stopped'?$('#resScr'):$('#gameScr')).classList.add('on');
        $('#nGame').classList.add('act');
      }else{
        $('#admScr').classList.add('on');
        $('#nAdmin').classList.add('act');
      }
    }
    window.nav=navTo;

    window.reset=function(){
      S.phase='idle';tmr.textContent='00.000';tmr.className='tmr';
      btn.textContent='INICIAR';btn.className='btn-go';btn.disabled=false;
      tmr.style.textShadow='none';
      $('#gameScr').classList.add('on');$('#resScr').classList.remove('on');
      $('#nGame').classList.add('act');
      $('#playerKey').value = ''; // Limpiar la clave anterior
    };

    function calibrate(){
      var det=$('#calDet');var pings=[];var fails=0;var i=0;
      function next(){
        if(i>=5){
          pings.sort(function(a,b){return a-b});
          var mid=pings.slice(1,-1);
          S.lat=Math.round(mid.reduce(function(a,b){return a+b},0)/mid.length);
          det.textContent='Latencia: '+S.lat+'ms — Listo!';
          $('#pingTxt').textContent='Ping: '+S.lat+'ms';
          setTimeout(function(){
            $('#calScr').classList.remove('on');
            $('#gameScr').classList.add('on','fi');
          },700);
          return;
        }
        det.textContent='Ping '+(i+1)+'/5...';
        var t=performance.now();
        api('ping').then(function(){
          pings.push(performance.now()-t);
          i++;next();
        }).catch(function(){
          fails++;
          if(fails>8){det.textContent='Error al conectar con la base de datos.';toast('Error de conexión');return}
          setTimeout(next,800);
        });
      }
      next();
    }

    window.handleBtn=function(ev){
      var trusted=ev&&ev.isTrusted===true;
      if(S.phase==='idle')doStart(trusted);
      else if(S.phase==='running')doStop(trusted);
    };

    function doStart(tr){
      var pKey = $('#playerKey').value.trim();
      if(!pKey) { toast('Por favor ingresa tu clave para jugar'); return; }

      btn.disabled=true;btn.textContent='...';
      api('start','POST', { key: pKey }).then(function(d){
        S.token=d.token;S.t0=performance.now();S.phase='running';
        btn.disabled=false;btn.textContent='DETENER';btn.classList.add('run');
        tmr.classList.add('run');
        var off=S.lat/2;var mk=performance.now()-off;
        clearInterval(S.iv);
        S.iv=setInterval(function(){
          var el=performance.now()-mk;tmr.textContent=fmt(el);
          tmr.style.textShadow=(el>9000&&el<11000)?'0 0 18px var(--cyan)':'none';
        },16);
      }).catch(function(e){
        toast(e.message);btn.disabled=false;btn.textContent='INICIAR';S.phase='idle';
      });
    }

    function doStop(tr){
      clearInterval(S.iv);
      var ce=Math.round(performance.now()-S.t0);
      btn.disabled=true;btn.textContent='...';btn.classList.remove('run');
      api('stop','POST',{token:S.token,isTrusted:tr,clientElapsed:ce}).then(function(r){
        S.phase='stopped';showResult(r);
        S.hist.unshift({t:r.serverElapsed,d:r.diff,w:r.isWinner});
        if(S.hist.length>10)S.hist.pop();
      }).catch(function(e){toast(e.message);window.reset()});
    }

    function showResult(r){
      var c=$('#resCard');var w=r.isWinner;var sus=r.status==='SOSPECHOSO';
      c.className='res-card fi '+(w?'win wburst':'lose');
      $('#resIcon').textContent=w?'\u{1F3C6}':(sus?'\u26A0\uFE0F':'\u23F1\uFE0F');
      $('#resTitle').textContent=w?'¡POSIBLE GANADOR!':(sus?'INTENTO SOSPECHOSO':'SIGUE INTENTANDO');
      $('#resTime').textContent=fmt(r.serverElapsed);
      $('#resDiff').textContent='Diferencia: '+r.diff+'ms del objetivo';
      var b=$('#resBadge');b.textContent=r.status;
      b.className='badge '+(r.status==='PENDIENTE_REVISION'?'badge-pend':r.status==='SOSPECHOSO'?'badge-sus':'badge-clean');
      tmr.textContent=fmt(r.serverElapsed);tmr.className='tmr '+(w?'win':'lose');tmr.style.textShadow='none';
      renderHist();
      $('#gameScr').classList.remove('on');$('#resScr').classList.add('on');
    }

    function renderHist(){
      if(!S.hist.length)return;
      $('#histWrap').style.display='block';
      var html='';
      for(var j=0;j<S.hist.length;j++){
        var h=S.hist[j];
        html+='<div class="h-item'+(h.w?' hw':'')+'"><span class="ht">'+fmt(h.t)+'</span><span class="hd">'+(h.w?'\u{1F3C6} ':'')+'\u00b1'+h.d+'ms</span></div>';
      }
      $('#histList').innerHTML=html;
    }

    var aKey='';
    window.admAuth=function(){
      aKey=$('#admKey').value;
      if(!aKey){toast('Ingresa la clave');return}
      admLoad('all');
    };
    function admLoad(f){
      api('audit','GET',null,'&key='+encodeURIComponent(aKey)+'&filter='+f).then(function(d){
        $('#admLogin').style.display='none';$('#admBody').style.display='block';
        renderAdm(d.entries);
      }).catch(function(e){toast(e.message)});
    }
    window.admFlt=function(f,b){
      document.querySelectorAll('.fbtn').forEach(function(x){x.classList.remove('act')});
      b.classList.add('act');admLoad(f);
    };
    function renderAdm(ents){
      var tb=$('#admTb');
      if(!ents||!ents.length){tb.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--dim);padding:18px">Sin registros</td></tr>';return}
      var html='';
      for(var j=0;j<ents.length;j++){
        var e=ents[j];
        var sc=(e.status==='SOSPECHOSO')?'var(--red)':(e.status==='PENDIENTE_REVISION'?'var(--gold)':'var(--green)');
        var t=e.timestamp?new Date(e.timestamp).toLocaleTimeString('es-MX'):'--';
        html+='<tr><td>'+t+'</td><td style="color:var(--cyan);font-weight:bold;">'+(e.playerKey||'--')+'</td><td title="'+(e.ip||'')+'">'+(e.ip||'--').substring(0,15)+'</td><td>'+(e.serverElapsed||0)+'ms</td><td>'+(e.diff||0)+'ms</td><td>'+(e.clientDrift!=null?e.clientDrift+'ms':'--')+'</td><td>'+(e.isTrustedEvent?'\u2705':'\u274C')+'</td><td style="color:'+sc+';font-weight:700">'+e.status+'</td></tr>';
      }
      tb.innerHTML=html;
    }

    $('#admKey').addEventListener('keydown',function(e){if(e.key==='Enter')window.admAuth()});

    var lastChk=Date.now();
    setInterval(function(){
      var now=Date.now();
      if(now-lastChk>5000&&S.phase==='running'){
        clearInterval(S.iv);S.phase='idle';
        toast('\u26A0\uFE0F Anomalía temporal. Sesión cancelada.');
        window.reset();
      }
      lastChk=now;
    },1000);

    calibrate();
  })();
  </script>
