(function(){
    var API='/api/game';
    var S={phase:'idle',token:null,t0:null,lat:0,iv:null,keys:[]};
    var $=function(s){return document.querySelector(s)};
    var aKey='';

    function toast(m){var t=$('#toast');t.textContent=m;t.classList.add('vis');setTimeout(function(){t.classList.remove('vis')},3000)}
    function fmt(ms){var s=Math.floor(ms/1000).toString().padStart(2,'0');var m=Math.floor(ms%1000).toString().padStart(3,'0');return s+'.'+m}

    function api(act,meth,body,p){
        return fetch(API+'?action='+act+(p||''),{method:meth||'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):null})
        .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||'Error');return d})});
    }

    window.navTo=function(n){
        document.querySelectorAll('.scr').forEach(function(x){x.classList.remove('on')});
        document.querySelectorAll('.nav-b').forEach(function(x){x.classList.remove('act')});
        if(n==='game'){$('#gameScr').classList.add('on');$('#nGame').classList.add('act')}
        else{$('#admScr').classList.add('on');$('#nAdmin').classList.add('act')}
    };

    function calibrate(){
        var t=performance.now();
        api('ping').then(function(){
            S.lat=Math.round(performance.now()-t);
            $('#calScr').classList.remove('on');
            $('#gameScr').classList.add('on');
        }).catch(function(){$('#calDet').textContent='Error de conexión'});
    }

    window.handleBtn=function(e){
        if(S.phase==='idle'){
            var k=$('#playerKey').value.trim();
            if(!k)return toast('Ingresa una clave');
            $('#btn').disabled=true;
            api('start','POST',{key:k}).then(function(d){
                S.token=d.token;S.t0=performance.now();S.phase='running';
                $('#btn').disabled=false;$('#btn').textContent='DETENER';$('#btn').classList.add('run');
                $('#tmr').classList.add('run');
                S.iv=setInterval(function(){$('#tmr').textContent=fmt(performance.now()-S.t0)},16);
            }).catch(function(err){toast(err.message);$('#btn').disabled=false});
        } else {
            clearInterval(S.iv);
            var ce=Math.round(performance.now()-S.t0);
            api('stop','POST',{token:S.token,isTrusted:e.isTrusted,clientElapsed:ce}).then(function(r){
                S.phase='idle';
                $('#tmr').textContent=fmt(r.serverElapsed);
                $('#tmr').className='tmr '+(r.isWinner?'win':'lose');
                $('#btn').textContent='INICIAR';$('#btn').classList.remove('run');$('#btn').disabled=false;
                toast(r.isWinner?'¡GANASTE!':'Fallaste por '+r.diff+'ms');
            }).catch(function(err){toast(err.message);location.reload()});
        }
    };

    window.admAuth=function(){
        aKey=$('#admKey').value;
        api('audit','GET',null,'&key='+aKey).then(function(d){
            $('#admLogin').style.display='none';$('#admBody').style.display='block';
            renderAdm(d.entries);
        }).catch(function(e){toast(e.message)});
    };

    window.generateKeys=function(){
        var c=$('#genCount').value;
        api('gen','GET',null,'&key='+aKey+'&count='+c).then(function(d){
            S.keys=d.keys;
            $('#btnDl').style.display='block';
            toast('Generadas '+d.keys.length+' claves');
        });
    };

    window.downloadKeys=function(){
        var b=new Blob([S.keys.join('\n')],{type:'text/plain'});
        var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='claves.txt';a.click();
    };

    function renderAdm(ents){
        $('#admTb').innerHTML=ents.map(function(e){
            return '<tr><td>'+e.playerKey+'</td><td>'+e.serverElapsed+'ms</td><td>'+e.diff+'ms</td><td>'+e.status+'</td></tr>';
        }).join('');
    }

    calibrate();
})();
