(function() {
"use strict";
var API="/api/v1";
var RC={na:"#4d9eff",eu:"#a78bfa",apac:"#00d4aa",mena:"#f5c518",latam:"#ff8c42"};
var RN={na:"N.Am",eu:"Europe",apac:"Asia",mena:"MENA",latam:"LatAm"};
function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function cvCls(v){return !v?"medium":v>=9?"critical":v>=7?"high":"medium";}
function g(id){return document.getElementById(id);}
function rel(iso){if(!iso)return"never";var diff=Date.now()-new Date(iso).getTime();var mm=Math.floor(diff/60000),hh=Math.floor(diff/3600000),dd=Math.floor(diff/86400000);return mm<60?mm+"m ago":hh<24?hh+"h ago":dd+"d ago";}
function showPage(name){document.querySelectorAll(".page").forEach(function(p){p.classList.remove("active");});document.querySelectorAll(".nvb").forEach(function(b){b.classList.remove("active");});var pg=g("page-"+name);if(pg)pg.classList.add("active");document.querySelectorAll("[data-page=\""+name+"\"]").forEach(function(b){b.classList.add("active");});if(name==="assets")loadAssets();if(name==="creds")loadCreds();if(name==="alerts")loadAlerts();}
document.querySelectorAll(".nvb").forEach(function(btn){btn.addEventListener("click",function(){showPage(btn.dataset.page);});});
function sw(tid,el){document.querySelectorAll(".tc").forEach(function(t){t.classList.remove("on");});document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("on");});g(tid).classList.add("on");el.classList.add("on");}
document.querySelectorAll(".tab").forEach(function(btn){btn.addEventListener("click",function(){sw(btn.dataset.tab,btn);});});
function uc(){var n=new Date(),pd=function(x){return String(x).padStart(2,"0");};g("ck").textContent=pd(n.getUTCHours())+":"+pd(n.getUTCMinutes())+":"+pd(n.getUTCSeconds())+" UTC";}
setInterval(uc,1000);uc();
function go(){
var fi=g("fi").value,fr=g("fr").value,fs=g("fs").value;
var qs="?industry="+fi+"&region="+fr+"&severity="+fs+"&limit=50";
fetch(API+"/threats"+qs).then(function(r){return r.json();}).then(function(d){
if(!d.success)return;var ev=d.data.events||[];
var crit=ev.filter(function(t){return t.severity==="critical";}).length;
g("fb").textContent=crit+" CRITICAL";g("c0").textContent=ev.length;
var th="";for(var ti=0;ti<ev.length;ti++){var te=ev[ti],tsev=esc(te.severity||"low");
th+="<div class=\"fi\"><div class=\"svb "+tsev+"\"></div><div style=\"flex:1;min-width:0\"><div class=\"fm\"><span class=\"bx "+tsev+"\">"+tsev.toUpperCase()+"</span><span style=\"background:#161b22;padding:1px 5px;border-radius:3px\">"+esc(te.source)+"</span></div><div class=\"ftl\">"+esc(te.title)+"</div><div class=\"fd\">"+esc((te.description||"").substring(0,100))+"</div></div></div>";}
g("fa").innerHTML=th||"<div class=\"lt\">No threats</div>";
var rcnt={};for(var ri=0;ri<ev.length;ri++){var rg=ev[ri].region||[];for(var rj=0;rj<rg.length;rj++){rcnt[rg[rj]]=(rcnt[rg[rj]]||0)+1;}}
var rsr=Object.entries(rcnt).sort(function(a,b){return b[1]-a[1];}).slice(0,5);var rmx=rsr.length?rsr[0][1]:1;
var rbh="";for(var ri2=0;ri2<rsr.length;ri2++){var rk=rsr[ri2][0],rv=rsr[ri2][1];rbh+="<div class=\"br\"><span class=\"bl\">"+esc(RN[rk]||rk)+"</span><div class=\"bt\"><div class=\"bf\" style=\"width:"+Math.round(rv/rmx*100)+"%;background:"+(RC[rk]||"#4d9eff")+"\"></div></div><span class=\"bc\">"+rv+"</span></div>";}
g("rb").innerHTML=rbh||"<div class=\"lt\">No data</div>";
var icnt={};for(var ii=0;ii<ev.length;ii++){var ig=ev[ii].industry||[];for(var ij=0;ij<ig.length;ij++){icnt[ig[ij]]=(icnt[ig[ij]]||0)+1;}}
var isr=Object.entries(icnt).sort(function(a,b){return b[1]-a[1];}).slice(0,7);var imx=isr.length?isr[0][1]:1;
var ibh="";for(var ii2=0;ii2<isr.length;ii2++){var ik=isr[ii2][0],iv=isr[ii2][1];ibh+="<div class=\"br\"><span class=\"bl\" style=\"text-transform:capitalize\">"+esc(ik)+"</span><div class=\"bt\"><div class=\"bf\" style=\"width:"+Math.round(iv/imx*100)+"%;background:linear-gradient(90deg,#4d9eff,#a78bfa)\"></div></div><span class=\"bc\">"+Math.round(iv/(ev.length||1)*100)+"%</span></div>";}
g("ib2").innerHTML=ibh||"<div class=\"lt\">No data</div>";
}).catch(function(){});
fetch(API+"/stats").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var sd=d.data;g("s0").textContent=sd.criticalThreats||"-";g("s1").textContent=(sd.activeIoCs||0).toLocaleString();g("s2").textContent=sd.threatActors||"-";g("s3").textContent=sd.zeroDayCVEs||"-";g("s4").textContent=sd.phishingKits||"-";}).catch(function(){});
fetch(API+"/health").then(function(r){return r.json();}).then(function(d){if(!d.feeds)return;var hfc={configured:"#00d4aa",active:"#00d4aa",public:"#4d9eff","no-key":"#f5c518"};var hh="<h3 style=\"font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px\">Health</h3>";Object.entries(d.feeds).forEach(function(fe){hh+="<div style=\"display:flex;justify-content:space-between;padding:3px 0;font-size:11px\"><span>"+fe[0]+"</span><span style=\"color:"+(hfc[fe[1]]||"#64748b")+"\">" +fe[1]+"</span></div>";});g("fh").innerHTML=hh;}).catch(function(){});
fetch(API+"/iocs?limit=100").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ic=d.data||[];g("c1").textContent=ic.filter(function(x){return x.source==="OTX";}).length;g("c2").textContent=ic.filter(function(x){return x.source==="URLhaus";}).length;g("c3").textContent=ic.filter(function(x){return x.source==="MalwareBazaar";}).length;g("c4").textContent=ic.filter(function(x){return x.source==="ThreatFox";}).length;g("c5").textContent=ic.filter(function(x){return x.source==="Feodo Tracker";}).length;var kc=function(c){return c>=90?"#00d4aa":c>=75?"#f5c518":"#ff3b5c";};var ih="";for(var ici=0;ici<ic.length;ici++){var icv=ic[ici];ih+="<tr><td><span style=\"background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px\">"+esc(icv.type||"-")+"</span></td><td style=\"color:#f5c518;word-break:break-all\">"+esc((icv.value||"").substring(0,48))+"</td><td style=\"color:"+kc(icv.confidence||0)+"\">"+(icv.confidence||"?")+"%</td><td style=\"color:#64748b\">"+esc(icv.first||"-")+"</td><td style=\"color:#64748b\">"+esc(icv.source||"-")+"</td></tr>";}g("ib").innerHTML=ih||"<tr><td colspan=\"5\" class=\"lt\">No IoCs</td></tr>";}).catch(function(){});
fetch(API+"/actors?limit=40").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ac=d.data||[];g("c7").textContent=ac.length;var ah="";for(var aci=0;aci<ac.length;aci++){var aa=ac[aci];ah+="<div class=\"ac\"><div class=\"an\">"+esc(aa.name||"?")+"</div><div class=\"asu\">"+esc(aa.nation||"?")+" - "+esc(aa.type||"APT")+"</div></div>";}g("ag").innerHTML=ah||"<div class=\"lt\">No actors</div>";}).catch(function(){});
fetch(API+"/cves?limit=20").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var cv=d.data||[];g("c8").textContent=cv.length;var ch="";for(var cvi=0;cvi<cv.length;cvi++){var cc=cv[cvi];ch+="<div class=\"ci\"><div class=\"cvs "+cvCls(cc.cvss)+"\">"+(cc.cvss||"N/A")+"</div><div><div style=\"font-family:monospace;font-size:11px\"><a href=\""+( cc.url||"#")+"\" target=\"_blank\" rel=\"noopener\" style=\"color:#4d9eff;text-decoration:none\">"+esc(cc.id)+"</a>"+(cc.exploited?"<span style=\"color:#ff3b5c;font-size:10px;margin-left:6px\">EXPLOITED</span>":"")+"</div><div class=\"ftl\">"+esc((cc.title||"").substring(0,90))+"</div></div></div>";}g("cl").innerHTML=ch||"<div class=\"lt\">No CVEs</div>";}).catch(function(){});
fetch(API+"/phishing?limit=20").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ph=d.data||[];g("c6").textContent=ph.length;g("s4").textContent=ph.length;var pph="";for(var phi=0;phi<ph.length;phi++){var pp=ph[phi];pph+="<div class=\"pi\"><div style=\"margin-top:2px;font-size:14px\">!</div><div><div class=\"ftl\">"+esc(pp.subject||("Phishing: "+pp.target))+"</div><div style=\"font-size:10px;color:#ff3b5c\">"+esc(pp.target||"-")+"</div><div style=\"font-size:11px;color:#64748b\">"+(pp.domains||1)+" domain(s)</div></div></div>";}g("pl").innerHTML=pph||"<div class=\"lt\">No phishing</div>";}).catch(function(){});
clearTimeout(window._rt);window._rt=setTimeout(function(){fetch(API+"/cache/flush",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(function(){}).then(go);},300000);
}
function rf(){fetch(API+"/cache/flush",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(function(){}).then(go);}
function loadAssets(){
fetch(API+"/monitor/status").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var st=d.data;var ipH="";(st.watchedIPs||[]).forEach(function(wip){ipH+="<span class=\"watched-chip\">"+esc(wip)+"<button onclick=\"window._rmW('ip','"+esc(wip)+"')\">x</button></span>";});g("watched-ips").innerHTML=ipH||"<div class=\"lt\">No IPs watched</div>";var dmH="";(st.watchedDomains||[]).forEach(function(wdm){dmH+="<span class=\"watched-chip\">"+esc(wdm)+"<button onclick=\"window._rmW('domain','"+esc(wdm)+"')\">x</button></span>";});g("watched-domains").innerHTML=dmH||"<div class=\"lt\">No domains watched</div>";if(st.lastScan)g("as-scan").textContent=rel(st.lastScan);}).catch(function(){});
fetch(API+"/monitor/assets").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var assets=d.data||[];var acrit=assets.filter(function(a){return a.riskLevel==="critical";}).length;var ahigh=assets.filter(function(a){return a.riskLevel==="high";}).length;g("as-crit").textContent=acrit;g("as-high").textContent=ahigh;g("as-total").textContent=assets.length;g("as-ports").textContent=assets.length;g("asset-badge").textContent=acrit+" CRITICAL";var at="";for(var asi=0;asi<assets.length;asi++){var aa2=assets[asi];var vs=Object.keys(aa2.vulns||{}).length?"<span style=\"color:#ff3b5c\">"+Object.keys(aa2.vulns).length+" CVE(s)</span>":"<span style=\"color:#00d4aa\">Clean</span>";at+="<tr><td style=\"font-family:monospace;color:#4d9eff\">"+esc(aa2.ip)+"</td><td style=\"color:#64748b\">"+esc((aa2.hostnames||[])[0]||aa2.org||"-")+"</td><td style=\"font-family:monospace\">"+esc(String(aa2.port||"-"))+"</td><td>"+esc(aa2.product||"Unknown")+(aa2.version?" <span style=\"color:#64748b\">"+esc(aa2.version)+"</span>":"")+"</td><td style=\"color:#64748b\">"+esc(aa2.country||"-")+"</td><td>"+vs+"</td><td><span class=\"risk-badge "+esc(aa2.riskLevel||"low")+"\">"+esc((aa2.riskLevel||"low").toUpperCase())+"</span></td></tr>";}g("asset-tbody").innerHTML=at||"<tr><td colspan=\"7\" class=\"lt\">No assets</td></tr>";}).catch(function(){});
}
window._rmW=function(wtype,wval){fetch(API+"/monitor/watchlist",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:wtype,value:wval})}).then(function(){if(wtype==="email"){if(typeof loadCreds==="function")loadCreds();}else{if(typeof loadAssets==="function")loadAssets();}}).catch(function(){});};
g("add-asset-btn").addEventListener("click",function(){var addIpVal=g("add-ip").value.trim(),addDmVal=g("add-domain").value.trim();if(!addIpVal&&!addDmVal){alert("Enter an IP or domain");return;}var abody={};if(addIpVal)abody.ip=addIpVal;if(addDmVal){abody.domain=addDmVal;abody.credDomain=addDmVal;}fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(abody)}).then(function(){g("add-ip").value="";g("add-domain").value="";loadAssets();}).catch(function(){});});
g("scan-btn").addEventListener("click",function(){var scanBtn=g("scan-btn");scanBtn.textContent="Scanning...";g("asset-badge").textContent="SCANNING";fetch(API+"/monitor/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).then(function(){setTimeout(function(){scanBtn.textContent="Run Scan Now";loadAssets();loadAlerts();},15000);}).catch(function(){scanBtn.textContent="Run Scan Now";});});

// ── Bulk Import Panel ────────────────────────────────────────────────────────
(function(){
var PREFIXES=[
"admin","administrator","webmaster","hostmaster","postmaster","abuse","noc","security",
"info","contact","hello","support","help","helpdesk","servicedesk","it","itsupport",
"hr","humanresources","recruitment","careers","jobs","payroll","training",
"ceo","cfo","cto","coo","ciso","president","director","manager","vp",
"finance","accounting","billing","accounts","treasury","audit",
"legal","compliance","privacy","dpo","risk","governance",
"sales","marketing","press","media","communications","pr","partnerships",
"procurement","purchasing","supply","vendors","facilities",
"operations","ops","devops","dev","engineering","tech","infrastructure",
"data","analytics","research","innovation",
"customerservice","customers","clients","feedback","complaints"
];
var bHdr=document.getElementById("bulk-header");
if(!bHdr)return;
bHdr.addEventListener("click",function(){
  var bd=document.getElementById("bulk-body");
  var bt=document.getElementById("bulk-toggle");
  if(!bd)return;
  var open=bd.style.display!=="none";
  bd.style.display=open?"none":"block";
  if(bt)bt.textContent=open?"Click to expand":"Click to collapse";
});
var tabPattern=document.getElementById("bulk-tab-pattern");
var tabCsv=document.getElementById("bulk-tab-csv");
var panePattern=document.getElementById("bulk-pane-pattern");
var paneCsv=document.getElementById("bulk-pane-csv");
function switchBulkTab(t){
  var isP=t==="pattern";
  if(tabPattern)tabPattern.className=isP?"btn btn-primary":"btn";tabPattern.style.cssText=isP?"font-size:11px":"font-size:11px;background:#1e2630;border:1px solid #2a3440";
  if(tabCsv)tabCsv.style.cssText=isP?"font-size:11px;background:#1e2630;border:1px solid #2a3440":"font-size:11px";tabCsv.className=isP?"btn":"btn btn-primary";
  if(panePattern)panePattern.style.display=isP?"block":"none";
  if(paneCsv)paneCsv.style.display=isP?"none":"block";
}
if(tabPattern)tabPattern.addEventListener("click",function(){switchBulkTab("pattern");});
if(tabCsv)tabCsv.addEventListener("click",function(){switchBulkTab("csv");});
var selectedEmails={};
function updateSelCount(){
  var n=Object.keys(selectedEmails).filter(function(k){return selectedEmails[k];}).length;
  var el=document.getElementById("bulk-sel-count");
  if(el)el.textContent="("+n+" selected)";
}
var previewBtn=document.getElementById("bulk-preview-btn");
if(previewBtn){previewBtn.addEventListener("click",function(){
  var dom=document.getElementById("bulk-domain");
  if(!dom)return;
  var domain=dom.value.trim().toLowerCase().replace(/^@/,"");
  if(!domain||domain.indexOf(".")<0){dom.style.borderColor="#ff3b5c";return;}
  dom.style.borderColor="";
  selectedEmails={};
  var listEl=document.getElementById("bulk-email-list");
  var previewArea=document.getElementById("bulk-preview-area");
  if(!listEl||!previewArea)return;
  listEl.innerHTML="";
  PREFIXES.forEach(function(p){
    var em=p+"@"+domain;
    selectedEmails[em]=true;
    var chip=document.createElement("label");
    chip.style.cssText="display:inline-flex;align-items:center;gap:4px;background:#0d1117;border:1px solid #2a3440;border-radius:4px;padding:3px 7px;cursor:pointer;font-size:11px;font-family:monospace;color:#e2e8f0;user-select:none";
    var cb=document.createElement("input");
    cb.type="checkbox";cb.checked=true;cb.style.accentColor="#a78bfa";
    (function(email,lbl,checkbox){
      checkbox.addEventListener("change",function(){
        selectedEmails[email]=checkbox.checked;
        lbl.style.borderColor=checkbox.checked?"#2a3440":"#1e2630";
        lbl.style.opacity=checkbox.checked?"1":"0.4";
        updateSelCount();
      });
    })(em,chip,cb);
    chip.appendChild(cb);
    chip.appendChild(document.createTextNode(em));
    listEl.appendChild(chip);
  });
  previewArea.style.display="block";
  updateSelCount();
});}
var selAll=document.getElementById("bulk-select-all");
var deselAll=document.getElementById("bulk-deselect-all");
if(selAll){selAll.addEventListener("click",function(){
  document.querySelectorAll("#bulk-email-list input[type=checkbox]").forEach(function(cb){cb.checked=true;var em=cb.parentElement.textContent.trim();selectedEmails[em]=true;cb.parentElement.style.opacity="1";cb.parentElement.style.borderColor="#2a3440";});
  updateSelCount();
});}
if(deselAll){deselAll.addEventListener("click",function(){
  document.querySelectorAll("#bulk-email-list input[type=checkbox]").forEach(function(cb){cb.checked=false;var em=cb.parentElement.textContent.trim();selectedEmails[em]=false;cb.parentElement.style.opacity="0.4";cb.parentElement.style.borderColor="#1e2630";});
  updateSelCount();
});}
var addSelBtn=document.getElementById("bulk-add-selected");
if(addSelBtn){addSelBtn.addEventListener("click",function(){
  var toAdd=Object.keys(selectedEmails).filter(function(k){return selectedEmails[k];});
  if(!toAdd.length){return;}
  var statusEl=document.getElementById("bulk-add-status");
  addSelBtn.disabled=true;addSelBtn.textContent="Adding "+toAdd.length+" emails...";
  var added=0,errors=0;
  function addNext(i){
    if(i>=toAdd.length){
      addSelBtn.disabled=false;addSelBtn.textContent="Add Selected to Monitor";
      if(statusEl)statusEl.textContent="Done: "+added+" added, "+errors+" errors.";
      setTimeout(function(){if(typeof loadCreds==="function")loadCreds();},500);
      return;
    }
    fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:toAdd[i]})})
    .then(function(){added++;if(statusEl)statusEl.textContent="Adding... "+added+"/"+toAdd.length;addNext(i+1);})
    .catch(function(){errors++;addNext(i+1);});
  }
  addNext(0);
});}
function parseEmails(raw){
  var lines=raw.replace(/,/g,"\n").split("\n");
  var emails=[];
  lines.forEach(function(l){
    var e=l.trim().toLowerCase();
    if(e&&e.indexOf("@")>0&&e.indexOf(".")>0)emails.push(e);
  });
  return emails;
}
var csvAddBtn=document.getElementById("bulk-csv-add");
if(csvAddBtn){csvAddBtn.addEventListener("click",function(){
  var ta=document.getElementById("bulk-paste");
  if(!ta)return;
  var emails=parseEmails(ta.value);
  var statusEl=document.getElementById("bulk-csv-status");
  if(!emails.length){if(statusEl)statusEl.textContent="No valid email addresses found.";return;}
  csvAddBtn.disabled=true;csvAddBtn.textContent="Adding "+emails.length+" emails...";
  var added=0,errors=0;
  function addNext(i){
    if(i>=emails.length){
      csvAddBtn.disabled=false;csvAddBtn.textContent="Add All Emails";
      if(statusEl)statusEl.textContent="Done: "+added+" added, "+errors+" skipped/errors.";
      ta.value="";
      setTimeout(function(){if(typeof loadCreds==="function")loadCreds();},500);
      return;
    }
    fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:emails[i]})})
    .then(function(){added++;if(statusEl)statusEl.textContent="Adding... "+added+"/"+emails.length;addNext(i+1);})
    .catch(function(){errors++;addNext(i+1);});
  }
  addNext(0);
});}
var fileInput=document.getElementById("bulk-file-input");
if(fileInput){fileInput.addEventListener("change",function(e){
  var file=e.target.files[0];
  if(!file)return;
  var reader=new FileReader();
  reader.onload=function(ev){
    var ta=document.getElementById("bulk-paste");
    if(ta)ta.value=ev.target.result;
    var statusEl=document.getElementById("bulk-csv-status");
    var count=parseEmails(ev.target.result).length;
    if(statusEl)statusEl.textContent="Loaded "+file.name+" -- "+count+" valid emails found. Click Add All Emails to import.";
  };
  reader.readAsText(file);
  fileInput.value="";
});}
})();
function loadCreds(){
fetch(API+"/credentials/status").then(function(r){return r.json();}).then(function(d){
if(!d.success)return;
var ems=d.emails||[];
var res=d.data||[];
var summ=d.summary||{};
g("cr-domains").textContent=ems.length||"-";
g("cr-accounts").textContent=(summ.exposedEmails||0).toLocaleString();
g("cr-breaches").textContent=(summ.uniqueBreaches||[]).length||0;
g("cr-critical").textContent=summ.criticalEmails||0;
if(res.length&&res[0].lastChecked)g("cr-last").textContent=rel(res[0].lastChecked);
var monList=document.getElementById("monitored-email-list");
var monCount=document.getElementById("mon-email-count");
if(monList){
  monList.innerHTML="";
  if(!ems.length){
    var noEm=document.createElement("div");
    noEm.style.cssText="color:#64748b;font-size:12px";
    noEm.textContent="No emails monitored yet -- add one above";
    monList.appendChild(noEm);
  }else{
    ems.forEach(function(em){
      var r4=res.filter(function(x){return x.email===em;})[0];
      var rl=r4?(r4.riskLevel==="clean"?"low":r4.riskLevel||"low"):"pending";
      var co=rl==="critical"?"#ff3b5c":rl==="high"?"#ff8c42":rl==="medium"?"#f5c518":rl==="low"?"#00d4aa":"#64748b";
      var chip=document.createElement("span");
      chip.className="watched-chip";
      var lbl=document.createElement("span");
      lbl.style.cssText="font-family:monospace;font-size:11px;color:"+co;
      lbl.textContent=em;
      chip.appendChild(lbl);
      var st=document.createElement("span");
      st.style.cssText="font-size:10px;margin-left:4px";
      if(r4&&r4.breachCount>0){st.style.color=co;st.textContent=r4.breachCount+" breach"+(r4.breachCount!==1?"es":"");}
      else if(r4&&r4.breachCount===0){st.style.color="#00d4aa";st.textContent="clean";}
      else{st.style.color="#64748b";st.textContent="checking...";}
      chip.appendChild(st);
      var xbtn=document.createElement("button");
      xbtn.className="rm-btn";
      xbtn.textContent="x";
      xbtn.style.marginLeft="6px";
      (function(email){
        xbtn.addEventListener("click",function(e){
          e.stopPropagation();
          xbtn.disabled=true;xbtn.textContent="...";
          fetch(API+"/monitor/watchlist",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:"email",value:email})})
          .then(function(){loadCreds();})
          .catch(function(){xbtn.disabled=false;xbtn.textContent="x";});
        });
      })(em);
      chip.appendChild(xbtn);
      monList.appendChild(chip);
    });
  }
  if(monCount)monCount.textContent=ems.length+(ems.length===1?" email":" emails");
}
var emH="";
var exposed=res.filter(function(em3){return em3.breachCount>0&&ems.indexOf(em3.email)>-1;});
var badge=document.getElementById("exposed-badge");
if(badge){badge.textContent=exposed.length+" EXPOSED";badge.style.display=exposed.length?"inline":"none";}
exposed.forEach(function(em3){
  (em3.breaches||[]).forEach(function(br){
    var erc2=em3.riskLevel==="clean"?"low":em3.riskLevel||"low";
    var ec2=erc2==="critical"?"#ff3b5c":erc2==="high"?"#ff8c42":erc2==="medium"?"#f5c518":"#00d4aa";
    emH+="<tr>";
    emH+="<td style=\"font-family:monospace;color:"+ec2+";font-size:11px\">"+esc(em3.email)+"</td>";
    emH+="<td style=\"text-align:center\">"+em3.breachCount+"</td>";
    emH+="<td><div style=\"font-weight:700;color:#e2e8f0\">"+esc(br.name||"-")+"</div>";
    emH+="<div style=\"font-size:10px;color:#64748b;margin-top:2px\">"+esc(br.domain||"-")+" | "+esc(br.breachDate||"-")+"</div>";
    emH+="<div style=\"font-size:10px;color:#ff8c42;margin-top:1px\">"+(br.pwnCount||0).toLocaleString()+" accounts exposed</div></td>";
    emH+="<td>";
    (br.dataClasses||[]).forEach(function(dc){
      var dcC=dc.toLowerCase().indexOf("password")>-1||dc.toLowerCase().indexOf("ssn")>-1||dc.toLowerCase().indexOf("financial")>-1?"#ff3b5c":dc.toLowerCase().indexOf("phone")>-1||dc.toLowerCase().indexOf("address")>-1?"#f5c518":"#64748b";
      emH+="<span style=\"display:inline-block;margin:1px 2px;padding:1px 5px;border-radius:3px;font-size:10px;border:1px solid "+dcC+";color:"+dcC+"\">"+esc(dc)+"</span>";
    });
    if(br.isSensitive)emH+="<br><span style=\"font-size:10px;color:#ff3b5c\">SENSITIVE</span>";
    emH+="</td>";
    emH+="<td><span class=\"risk-badge "+erc2+"\">"+erc2.toUpperCase()+"</span></td>";
    emH+="</tr>";
  });
});
g("exposed-emails").innerHTML=emH||"<tr><td colspan=\"5\" class=\"lt\">No breaches found for monitored emails</td></tr>";
var sumH="";
if(!res.length){
  sumH="<div style=\"padding:16px;color:#64748b;font-size:12px\">Add any email above to check against 700+ known breaches.<br><span style=\"color:#4d9eff\">Powered by HaveIBeenPwned</span></div>";
}else{
  res.forEach(function(em2){
    var erc=em2.riskLevel==="clean"?"low":em2.riskLevel||"low";
    var ecol=erc==="critical"?"#ff3b5c":erc==="high"?"#ff8c42":erc==="medium"?"#f5c518":"#00d4aa";
    sumH+="<div style=\"padding:10px 13px;border-bottom:1px solid #1e2630;display:flex;justify-content:space-between;align-items:flex-start\">";
    sumH+="<div><div style=\"font-family:monospace;font-size:12px;font-weight:700;color:"+ecol+";margin-bottom:4px\">"+esc(em2.email)+"</div>";
    if(em2.breachCount>0){sumH+="<div style=\"font-size:11px;color:#64748b\">Found in: ";(em2.breachNames||[]).slice(0,6).forEach(function(bn){sumH+="<span class=\"tag\">"+esc(bn)+"</span>";});if((em2.breachNames||[]).length>6)sumH+="<span class=\"tag\">+"+(em2.breachNames.length-6)+" more</span>";sumH+="</div>";}
    else{sumH+="<div style=\"font-size:11px;color:#00d4aa\">No breaches found</div>";}
    sumH+="</div><span class=\"risk-badge "+erc+"\">"+(em2.breachCount||0)+" breach"+(em2.breachCount!==1?"es":"")+"</span></div>";
  });
}
var cs=document.getElementById("cred-summary");if(cs)cs.innerHTML=sumH;
}).catch(function(){});
fetch(API+"/credentials/breaches").then(function(r){return r.json();}).then(function(d){
if(!d.success)return;var brs=d.data||[],gbh="";
brs.forEach(function(gbr){
  gbh+="<div class=\"breach-item\"><div class=\"breach-name\">"+esc(gbr.name)+"</div>";
  gbh+="<div class=\"breach-meta\">"+esc(gbr.domain||"-")+" - "+esc(gbr.breachDate||"-")+" - <span style=\"color:#ff8c42\">"+(gbr.pwnCount||0).toLocaleString()+" accounts</span></div>";
  gbh+="<div style=\"margin-top:4px\">"+(gbr.dataClasses||[]).map(function(dc){return "<span class=\"tag\">"+esc(dc)+"</span>";}).join("")+"</div></div>";
});
var gb=document.getElementById("global-breaches");if(gb)gb.innerHTML=gbh||"<div class=\"lt\">No data</div>";
}).catch(function(){});
}

// Collapsible sections on creds page
(function(){
  function makeToggle(headerId,bodyId,toggleId){
    var h=document.getElementById(headerId);
    if(!h)return;
    h.addEventListener("click",function(){
      var b=document.getElementById(bodyId);
      var t=document.getElementById(toggleId);
      if(!b)return;
      var open=b.style.display!=="none";
      b.style.display=open?"none":"block";
      if(t)t.textContent=open?"Click to expand":"Click to collapse";
    });
  }
  makeToggle("summary-header","summary-body","summary-toggle");
  makeToggle("breaches-header","breaches-body","breaches-toggle");
})();

g("add-cred-btn").addEventListener("click",function(){var credEmailVal=g("add-cred-email").value.trim();if(!credEmailVal||credEmailVal.indexOf("@")<0){alert("Enter a valid email");return;}var credBtn=g("add-cred-btn");credBtn.textContent="Checking...";fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:credEmailVal})}).then(function(){return fetch(API+"/credentials/email/"+encodeURIComponent(credEmailVal));}).then(function(r){return r.json();}).then(function(){g("add-cred-email").value="";credBtn.textContent="+ Monitor Email";loadCreds();}).catch(function(){credBtn.textContent="+ Monitor Email";});});
g("check-btn").addEventListener("click",function(){var checkBtn=g("check-btn");checkBtn.textContent="Checking...";fetch(API+"/monitor/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).then(function(){setTimeout(function(){checkBtn.textContent="Check All Now";loadCreds();},8000);}).catch(function(){checkBtn.textContent="Check All Now";});});
function loadAlerts(){fetch(API+"/monitor/alerts").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var alts=d.data||[];var acnt=alts.length,adot=g("alert-count");if(acnt>0){adot.textContent=acnt;adot.style.display="inline-block";}else{adot.style.display="none";}g("alerts-badge").textContent=acnt+" ALERTS";if(!alts.length){g("alerts-list").innerHTML="<div class=\"lt\">No alerts yet.</div>";return;}var aicons={new_port:"[PORT]",new_vuln:"[CVE]",credential_leak:"[CRED]",critical_asset:"[ASSET]"};var asevC={critical:"#ff3b5c",high:"#ff8c42",medium:"#f5c518",low:"#00d4aa"};var alh="";for(var ali=0;ali<alts.length;ali++){var alt=alts[ali],asc=asevC[alt.severity]||"#64748b";alh+="<div class=\"alert-item\"><div style=\"font-family:monospace;font-size:11px;color:"+asc+";flex-shrink:0;padding-top:2px\">"+(aicons[alt.type]||"[!]")+"</div><div style=\"flex:1\"><div class=\"alert-msg\">"+esc(alt.message)+"</div><div class=\"alert-time\"><span style=\"color:"+asc+"\">"+esc((alt.severity||"").toUpperCase())+"</span> &bull; "+esc(rel(alt.timestamp))+"</div></div></div>";}g("alerts-list").innerHTML=alh;}).catch(function(){});}
g("clear-alerts-btn").addEventListener("click",loadAlerts);
g("fi").addEventListener("change",go);g("fr").addEventListener("change",go);g("fs").addEventListener("change",go);g("rfbtn").addEventListener("click",rf);
setInterval(function(){var ap=document.querySelector(".page.active");if(!ap)return;if(ap.id==="page-assets")loadAssets();if(ap.id==="page-creds")loadCreds();if(ap.id==="page-alerts")loadAlerts();},30000);
go();
})();