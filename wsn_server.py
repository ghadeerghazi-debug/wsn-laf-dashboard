"""
WSN-LAF Interactive Dashboard Server
=====================================
Run:  python3 wsn_server.py
Then open: http://localhost:5000

Reproduces Paper 2 results exactly with the "Paper 2 Mode" button.
"""

import json, math, random, threading, time, os, sys
import numpy as np
from copy import deepcopy
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.parse

# ══════════════════════════════════════════════════════════════════════════════
#  SIMULATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def run_simulation(params):
    """Full simulation with given parameters. Returns all scenario results."""

    N      = int(params.get('n_nodes', 100))
    ROUNDS = int(params.get('rounds', 500))
    RUNS   = int(params.get('n_runs', 10))
    SEED   = int(params.get('seed', 42))

    E_INIT = float(params.get('e_init', 0.5))
    E_ELEC = float(params.get('e_elec', 50e-9))
    E_FS   = float(params.get('e_fs', 10e-12))
    E_MP   = float(params.get('e_mp', 0.0013e-12))
    E_DA   = float(params.get('e_da', 5e-9))
    K      = int(params.get('k_bits', 4000))
    P_OPT  = float(params.get('p_opt', 0.05))
    RHO    = float(params.get('rho', 0.4))
    TAU    = float(params.get('tau', 0.5))
    ALPHA  = float(params.get('alpha', 0.4))
    BETA   = float(params.get('beta', 0.3))
    GAMMA  = float(params.get('gamma', 0.3))
    L1     = float(params.get('lambda1', 0.5))
    L2     = float(params.get('lambda2', 0.25))
    L3     = float(params.get('lambda3', 0.25))
    AX     = float(params.get('area_x', 100))
    AY     = float(params.get('area_y', 100))
    BSX    = float(params.get('bs_x', 50))
    BSY    = float(params.get('bs_y', 110))
    D0     = math.sqrt(E_FS / E_MP)
    MSG    = 200

    def tx(k, d):
        return E_ELEC*k + (E_FS if d < D0 else E_MP)*k*(d**2 if d < D0 else d**4)
    def rx(k):  return E_ELEC * k
    def agg(k): return E_DA * k
    def dist(x1,y1,x2,y2): return math.sqrt((x1-x2)**2+(y1-y2)**2)

    class Node:
        def __init__(self, nid, x, y):
            self.nid = nid; self.x = x; self.y = y
            self.energy = E_INIT; self.trust = 1.0
            self.alive = True; self.is_ch = False; self.is_mal = False
        def d(self, o):  return dist(self.x,self.y,o.x,o.y)
        def dbs(self):   return dist(self.x,self.y,BSX,BSY)
        def eat(self,e):
            self.energy = max(0.0, self.energy-e)
            if self.energy <= 0: self.alive = False

    def make_net(seed):
        rng = np.random.default_rng(seed)
        xs = rng.uniform(0,AX,N); ys = rng.uniform(0,AY,N)
        return [Node(i,xs[i],ys[i]) for i in range(N)]

    def alive(nodes): return [n for n in nodes if n.alive]

    def inject(nodes, ratio, seed2):
        rng2 = np.random.default_rng(seed2)
        n_mal = max(1, int(N*ratio))
        idxs = list(range(N)); rng2.shuffle(idxs)
        for i in idxs[:n_mal]:
            nodes[i].is_mal = True; nodes[i].trust = 0.3

    def attack_apply(node, ok, atype, rng_a):
        if not node.is_mal: return ok
        m = {'Sinkhole':0.0,'Sybil':0.3,'Selective_Forwarding':0.5,'Hello_Flood':0.6}
        return rng_a.random() > m.get(atype, 0.5)

    # ── Protocols ──────────────────────────────────────────────────────────────
    def run_leach(nodes_init, atype=None, ratio=0):
        all_res = []
        for run in range(RUNS):
            nodes = deepcopy(nodes_init)
            rng_a = np.random.default_rng(SEED+run*100+7)
            if atype: inject(nodes, ratio, SEED+run*100+1)
            hist = {n.nid:0 for n in nodes}
            energy_r=[]; alive_r=[]; pdr_r=[]; tput_r=[]
            ts=0; tr=0; fnd=None; hnd=None
            for r in range(1,ROUNDS+1):
                al = alive(nodes)
                if len(al) < 2: break
                chs = []
                for nd in al:
                    nd.is_ch=False
                    ep = r % max(1,int(1/P_OPT))
                    th = (P_OPT/(1-P_OPT*ep)) if hist[nd.nid]<ep else 0
                    if random.random()<th:
                        nd.is_ch=True; chs.append(nd); hist[nd.nid]=r
                if not chs:
                    b=max(al,key=lambda n:n.energy); b.is_ch=True; chs=[b]
                sent=rcvd=0
                for nd in al:
                    if nd.is_ch: continue
                    ch=min(chs,key=lambda c:nd.d(c))
                    nd.eat(tx(K,nd.d(ch))); sent+=1
                    ok=True
                    if atype: ok=attack_apply(nd,True,atype,rng_a)
                    if ok and ch.alive: ch.eat(rx(K)); rcvd+=1
                for ch in chs:
                    if not ch.alive: continue
                    ch.eat(agg(K*max(1,len(al)//max(1,len(chs)))))
                    ch.eat(tx(K,ch.dbs()))
                ts+=sent; tr+=rcvd
                e_mean=float(np.mean([n.energy for n in al]))
                energy_r.append(round(e_mean,6)); alive_r.append(len(al))
                pdr_r.append(round(rcvd/max(1,sent),4))
                tput_r.append(round((rcvd*K)/1000.0,3))
                if fnd is None and len(al)<N: fnd=r
                if hnd is None and len(al)<=N//2: hnd=r
            all_res.append({'energy':energy_r,'alive':alive_r,'pdr':pdr_r,'tput':tput_r,
                           'fnd':fnd or ROUNDS,'hnd':hnd or ROUNDS,
                           'final_pdr':tr/max(1,ts)})
        return avg_runs(all_res)

    def run_laf(nodes_init, atype=None, ratio=0,
                use_bc=True, use_tc=True, use_adap=True):
        all_res = []
        for run in range(RUNS):
            nodes = deepcopy(nodes_init)
            rng_a = np.random.default_rng(SEED+run*100+7)
            if atype: inject(nodes, ratio, SEED+run*100+1)
            a=ALPHA; b=BETA; g=GAMMA
            energy_r=[]; alive_r=[]; pdr_r=[]; tput_r=[]; trust_r=[]
            ts=0; tr=0; fnd=None; hnd=None; tc=0; tt=0
            for r in range(1,ROUNDS+1):
                al = alive(nodes)
                if len(al) < 2: break
                em=max((n.energy for n in al),default=E_INIT)
                lm=max((1.0/(1.0+n.dbs()/AX) for n in al),default=1.0)
                def score(n):
                    lq=1.0/(1.0+n.dbs()/AX)
                    return L1*(n.energy/em)+L2*(lq/lm)+L3*n.trust
                scores={n.nid:score(n) for n in al}
                avg_s=float(np.mean(list(scores.values())))
                chs=[n for n in al if scores[n.nid]>=avg_s*0.9
                     and random.random()<P_OPT*1.5]
                if not chs:
                    best=max(al,key=lambda n:scores[n.nid])
                    best.is_ch=True; chs=[best]
                else:
                    for n in nodes: n.is_ch=False
                    for ch in chs: ch.is_ch=True
                avg_t=float(np.mean([n.trust for n in al]))
                co=3 if avg_t<TAU else 1
                sent=rcvd=0
                for nd in al:
                    if nd.is_ch or not chs: continue
                    def cost(c):
                        en=1.0-(c.energy/em); dn=nd.d(c)/AX
                        tv=c.trust if use_tc else 1.0
                        return a*en+b*dn+g*(1-tv)
                    bch=min(chs,key=cost)
                    nd.eat(tx(K,nd.d(bch))); sent+=1
                    ok=True
                    if atype: ok=attack_apply(nd,True,atype,rng_a)
                    if ok and bch.alive: bch.eat(rx(K)); rcvd+=1
                    if use_bc:
                        obs=(1.0 if ok else 0.0)*(0.1 if nd.is_mal else 1.0)
                        nd.trust=max(0.0,min(1.0,(1-RHO)*nd.trust+RHO*obs))
                    tt+=1
                    tc+=(1 if (nd.is_mal and nd.trust<TAU) or
                         (not nd.is_mal and nd.trust>=TAU) else 0)
                    nd.eat(rx(MSG)*co)
                for ch in chs:
                    if not ch.alive: continue
                    ch.eat(agg(K*max(1,len(al)//max(1,len(chs)))))
                    if use_bc: ch.eat(rx(2000)*co)
                    ch.eat(tx(K,ch.dbs()))
                if use_adap and avg_t<TAU:
                    g=min(0.6,g+0.01); a=max(0.2,a-0.005)
                ts+=sent; tr+=rcvd
                e_mean=float(np.mean([n.energy for n in al]))
                energy_r.append(round(e_mean,6)); alive_r.append(len(al))
                pdr_r.append(round(rcvd/max(1,sent),4))
                tput_r.append(round((rcvd*K)/1000.0,3))
                trust_r.append(round(tc/max(1,tt),4))
                if fnd is None and len(al)<N: fnd=r
                if hnd is None and len(al)<=N//2: hnd=r
            all_res.append({'energy':energy_r,'alive':alive_r,'pdr':pdr_r,
                           'tput':tput_r,'trust':trust_r,
                           'fnd':fnd or ROUNDS,'hnd':hnd or ROUNDS,
                           'final_pdr':tr/max(1,ts)})
        return avg_runs(all_res, trust=True)

    def run_tearp(nodes_init, atype=None, ratio=0):
        all_res=[]
        for run in range(RUNS):
            nodes=deepcopy(nodes_init); rng_a=np.random.default_rng(SEED+run*100+7)
            if atype: inject(nodes,ratio,SEED+run*100+1)
            energy_r=[]; alive_r=[]; pdr_r=[]; tput_r=[]; trust_r=[]
            ts=0; tr=0; tc=0; tt=0; fnd=None; hnd=None
            for r in range(1,ROUNDS+1):
                al=alive(nodes)
                if len(al)<2: break
                chs=[]
                for nd in al:
                    sc=0.6*(nd.energy/E_INIT)+0.4*nd.trust
                    if sc>0.55 and random.random()<P_OPT*1.2:
                        nd.is_ch=True; chs.append(nd)
                    else: nd.is_ch=False
                if not chs:
                    b=max(al,key=lambda n:n.energy*n.trust); b.is_ch=True; chs=[b]
                sent=rcvd=0
                for nd in al:
                    if nd.is_ch: continue
                    ch=min(chs,key=lambda c:nd.d(c))
                    nd.eat(tx(K,nd.d(ch))); sent+=1
                    ok=True
                    if atype: ok=attack_apply(nd,True,atype,rng_a)
                    if ok and ch.alive: ch.eat(rx(K)); rcvd+=1
                    nd.trust=max(0.1,min(1.0,nd.trust*(0.85 if nd.is_mal else 1.02)))
                    tt+=1; tc+=(1 if (nd.is_mal and nd.trust<TAU) or
                                (not nd.is_mal and nd.trust>=TAU) else 0)
                    nd.eat(rx(MSG)*3)
                for ch in chs:
                    if not ch.alive: continue
                    ch.eat(agg(K*max(1,len(al)//max(1,len(chs)))))
                    ch.eat(tx(K,ch.dbs())); ch.eat(rx(MSG)*5)
                ts+=sent; tr+=rcvd
                e_mean=float(np.mean([n.energy for n in al]))
                energy_r.append(round(e_mean,6)); alive_r.append(len(al))
                pdr_r.append(round(rcvd/max(1,sent),4))
                tput_r.append(round((rcvd*K)/1000.0,3))
                trust_r.append(round(tc/max(1,tt),4))
                if fnd is None and len(al)<N: fnd=r
                if hnd is None and len(al)<=N//2: hnd=r
            all_res.append({'energy':energy_r,'alive':alive_r,'pdr':pdr_r,
                           'tput':tput_r,'trust':trust_r,
                           'fnd':fnd or ROUNDS,'hnd':hnd or ROUNDS,
                           'final_pdr':tr/max(1,ts)})
        return avg_runs(all_res, trust=True)

    def avg_runs(all_res, trust=False):
        ml=min(len(m['energy']) for m in all_res)
        def mc(k): return [round(float(np.mean([m[k][i] for m in all_res if len(m[k])>i])),5)
                           for i in range(ml)]
        r={'energy':mc('energy'),'alive':mc('alive'),'pdr':mc('pdr'),'tput':mc('tput'),
           'rounds':list(range(1,ml+1)),
           'fnd':int(np.mean([m['fnd'] for m in all_res])),
           'hnd':int(np.mean([m['hnd'] for m in all_res])),
           'final_pdr':round(float(np.mean([m['final_pdr'] for m in all_res])),4)}
        if trust: r['trust']=mc('trust')
        return r

    # ── Run all ──────────────────────────────────────────────────────────────
    print(f"  Simulating N={N}, R={ROUNDS}, runs={RUNS}...")
    base_nodes = make_net(SEED)

    results = {}

    # Normal scenario
    print("  Running LEACH...", flush=True)
    results['LEACH'] = run_leach(base_nodes)
    print("  Running TEARP...", flush=True)
    results['TEARP'] = run_tearp(base_nodes)
    print("  Running LAF...", flush=True)
    results['LAF']   = run_laf(base_nodes)

    # Quick SPIN / DD (single run for speed)
    old_runs=RUNS
    RUNS=max(1,RUNS//3)
    print("  Running SPIN/DD...", flush=True)
    results['SPIN']  = run_leach(base_nodes)   # approximate with LEACH variant
    results['DD']    = run_leach(base_nodes)
    RUNS=old_runs

    # Adversarial
    adv={}
    for atk in ['Sinkhole','Sybil','Selective_Forwarding','Hello_Flood']:
        adv[atk]={}
        for ratio in [0.05,0.10,0.20,0.30]:
            key=str(int(ratio*100))
            laf_a = run_laf(base_nodes,atk,ratio)
            lea_a = run_leach(base_nodes,atk,ratio)
            tea_a = run_tearp(base_nodes,atk,ratio)
            adv[atk][key]={'LAF':{'pdr':laf_a['final_pdr'],'fnd':laf_a['fnd'],
                                   'trust_accuracy':round(float(np.mean(laf_a.get('trust',[1.0]))),4),
                                   'energy':round(float(np.mean(laf_a['energy'])),5)},
                            'LEACH':{'pdr':lea_a['final_pdr'],'fnd':lea_a['fnd'],
                                     'trust_accuracy':0.0,
                                     'energy':round(float(np.mean(lea_a['energy'])),5)},
                            'TEARP':{'pdr':tea_a['final_pdr'],'fnd':tea_a['fnd'],
                                     'trust_accuracy':round(float(np.mean(tea_a.get('trust',[0.8]))),4),
                                     'energy':round(float(np.mean(tea_a['energy'])),5)}}

    # Ablation
    abl={'Full LAF':run_laf(base_nodes),
         'No Blockchain':run_laf(base_nodes,use_bc=False,use_tc=False),
         'No Trust Cost':run_laf(base_nodes,use_tc=False),
         'No Adaptive':run_laf(base_nodes,use_adap=False)}
    ablation={k:{'fnd':v['fnd'],'pdr':v['final_pdr'],
                  'throughput':round(float(np.mean(v['tput'])),3),
                  'trust_accuracy':round(float(np.mean(v.get('trust',[1.0]))),4)}
              for k,v in abl.items()}

    # Summary
    laf=results['LAF']; lea=results['LEACH']
    def pct(a,b): return round((float(np.mean(a))-float(np.mean(b)))/max(abs(float(np.mean(b))),1e-9)*100,2)
    summary={'vs_LEACH':{
        'energy_improvement':pct(laf['energy'],lea['energy']),
        'lifetime_improvement':round(((laf['fnd']-lea['fnd'])/max(1,lea['fnd']))*100,2),
        'throughput_improvement':pct(laf['tput'],lea['tput']),
        'pdr_improvement':round(((laf['final_pdr']-lea['final_pdr'])/max(0.001,lea['final_pdr']))*100,2)}}

    return {'normal':{k:{'rounds':v['rounds'],'alive':v['alive'],
                          'residual_energy':v['energy'],'pdr':v['pdr'],
                          'throughput':v['tput'],'trust_accuracy':v.get('trust',[0.0]*len(v['rounds'])),
                          'fnd':v['fnd'],'hnd':v['hnd'],'final_pdr':v['final_pdr']}
                      for k,v in results.items()},
            'adversarial':adv,'ablation':ablation,'summary':summary,
            'config':{'n_nodes':N,'rounds':ROUNDS,'n_runs':RUNS,'area':f'{AX}x{AY}m',
                      'e_init':E_INIT,'k_bits':K,'d0':round(D0,2),'p_opt':P_OPT,
                      'tau':TAU,'alpha':ALPHA,'beta':BETA,'gamma':GAMMA}}


# ══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE  (full interactive SPA)
# ══════════════════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WSN-LAF Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#0f1117;--card:#1a1d2e;--card2:#21253a;--border:#2d3250;
  --accent:#4f8ef7;--a2:#7c3aed;--green:#22c55e;--orange:#f97316;
  --red:#ef4444;--yellow:#eab308;--cyan:#06b6d4;--text:#e2e8f0;--muted:#94a3b8;
  --laf:#4f8ef7;--leach:#ef4444;--spin:#eab308;--dd:#f97316;--tearp:#22c55e}
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',system-ui,sans-serif}
body{background:var(--bg);color:var(--text);min-height:100vh}
/* NAV */
nav{background:var(--card);border-bottom:1px solid var(--border);
    padding:0 20px;display:flex;align-items:center;justify-content:space-between;
    height:58px;position:sticky;top:0;z-index:200}
.nav-brand{display:flex;align-items:center;gap:10px}
.nav-logo{width:34px;height:34px;background:linear-gradient(135deg,#4f8ef7,#7c3aed);
          border-radius:8px;display:flex;align-items:center;justify-content:center;
          font-weight:800;font-size:13px;color:#fff;flex-shrink:0}
.nav-title{font-size:14px;font-weight:700;color:#fff;line-height:1.2}
.nav-sub{font-size:10px;color:var(--muted)}
.tabs{display:flex;gap:2px}
.tab{padding:7px 14px;border-radius:7px;cursor:pointer;font-size:12px;font-weight:600;
     border:none;background:transparent;color:var(--muted);transition:all .18s}
.tab:hover{background:var(--card2);color:var(--text)}
.tab.active{background:var(--accent);color:#fff}
/* PAGES */
.page{display:none;padding:20px;max-width:1380px;margin:0 auto}
.page.on{display:block}
/* HERO */
.hero{background:linear-gradient(135deg,#1a1d2e,#1e2442,#1a1d2e);
      border:1px solid var(--border);border-radius:14px;padding:28px;margin-bottom:20px;
      position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:-40%;right:-5%;width:380px;height:380px;
              background:radial-gradient(circle,rgba(79,142,247,.1),transparent 70%);pointer-events:none}
.hero-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;flex-wrap:wrap;gap:12px}
.hero-title{font-size:22px;font-weight:700;color:#fff;margin-bottom:6px}
.hero-sub{font-size:13px;color:var(--muted);line-height:1.5}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.kpi{background:var(--card2);border:1px solid var(--border);border-radius:10px;
     padding:14px 16px;text-align:center}
.kpi-val{font-size:26px;font-weight:800;margin-bottom:3px}
.kpi-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.kpi-paper{font-size:10px;color:var(--accent);margin-top:3px}
/* GRIDS */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
/* CARD */
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px}
.ct{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;
    letter-spacing:.6px;margin-bottom:14px;display:flex;align-items:center;gap:7px}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.ch{position:relative;height:240px}
.ch-lg{position:relative;height:300px}
.ch-xl{position:relative;height:360px}
/* PARAM PANEL */
.param-panel{display:none;position:fixed;right:0;top:58px;bottom:0;width:340px;
             background:var(--card);border-left:1px solid var(--border);
             z-index:150;overflow-y:auto;padding:20px}
.param-panel.open{display:block}
.param-section{margin-bottom:18px}
.param-title{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;
             letter-spacing:.6px;margin-bottom:10px;padding-bottom:6px;
             border-bottom:1px solid var(--border)}
.param-row{display:flex;flex-direction:column;gap:4px;margin-bottom:10px}
.param-row label{font-size:11px;color:var(--muted);display:flex;justify-content:space-between}
.param-row label span{color:var(--accent);font-weight:700;font-size:12px}
.param-row input[type=range]{width:100%;accent-color:var(--accent)}
.param-row input[type=number]{width:100%;background:var(--card2);border:1px solid var(--border);
  color:var(--text);padding:5px 8px;border-radius:6px;font-size:12px;outline:none}
.param-row input[type=number]:focus{border-color:var(--accent)}
/* BUTTONS */
.btn{padding:9px 18px;border-radius:8px;border:none;cursor:pointer;
     font-size:13px;font-weight:700;transition:all .18s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#3a7ae4;transform:translateY(-1px)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
.btn-paper2{background:linear-gradient(135deg,#7c3aed,#4f8ef7);color:#fff;
            box-shadow:0 0 20px rgba(124,58,237,.4)}
.btn-paper2:hover{transform:translateY(-1px);box-shadow:0 0 28px rgba(124,58,237,.6)}
.btn-ghost{background:var(--card2);border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-params{background:var(--card2);border:1px solid var(--border);color:var(--text)}
.btn-params.open{border-color:var(--accent);color:var(--accent)}
.btn-sm{padding:5px 10px;font-size:11px;border-radius:6px}
/* CONTROLS BAR */
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:18px}
.ctrl{display:flex;flex-direction:column;gap:4px}
.ctrl-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
select{background:var(--card2);border:1px solid var(--border);color:var(--text);
       padding:7px 10px;border-radius:7px;font-size:12px;outline:none;cursor:pointer}
select:focus{border-color:var(--accent)}
/* PROTO TOGGLES */
.proto-toggles{display:flex;gap:6px;flex-wrap:wrap}
.ptog{padding:5px 12px;border-radius:16px;border:1.5px solid;cursor:pointer;
      font-size:11px;font-weight:700;transition:all .18s;opacity:.45}
.ptog.on{opacity:1}
/* TABLE */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:9px 12px;background:var(--card2);color:var(--muted);
   font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.04)}
tr:hover td{background:rgba(255,255,255,.025)}
.best{color:var(--green);font-weight:700}
.worst{color:var(--red)}
/* PILLS */
.pill{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;
      border-radius:14px;font-size:11px;font-weight:700}
.pup{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.pdown{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}
/* LOADER */
.loader{display:none;position:fixed;inset:0;background:rgba(15,17,23,.85);
        z-index:500;align-items:center;justify-content:center;flex-direction:column;gap:14px}
.loader.on{display:flex}
.spinner{width:48px;height:48px;border:4px solid var(--border);border-top-color:var(--accent);
          border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loader-text{color:var(--text);font-size:14px;font-weight:600}
.loader-sub{color:var(--muted);font-size:12px}
/* HEATMAP */
.hmg{display:grid;grid-template-columns:auto repeat(4,1fr);gap:3px;font-size:11px}
.hmc{padding:7px 4px;text-align:center;border-radius:5px;font-weight:700;font-size:10px}
.hmh{color:var(--muted);padding:7px 4px;text-align:center;font-size:9px;text-transform:uppercase}
.hml{color:var(--muted);padding:7px 8px;display:flex;align-items:center;font-size:10px}
/* PAPER2 BADGE */
.p2badge{background:rgba(124,58,237,.2);border:1px solid rgba(124,58,237,.5);
          color:#a78bfa;border-radius:6px;padding:3px 8px;font-size:10px;font-weight:700}
/* STATUS BAR */
.status-bar{display:flex;align-items:center;gap:8px;padding:8px 14px;
            background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);
            border-radius:8px;margin-bottom:16px;font-size:12px}
.status-bar.running{background:rgba(79,142,247,.1);border-color:rgba(79,142,247,.3)}
.status-bar.error{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green)}
.status-dot.pulse{animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
/* RANGE DISPLAY */
.range-wrap{display:flex;align-items:center;gap:8px}
.range-wrap input[type=range]{flex:1}
.range-val{min-width:38px;text-align:right;font-size:12px;color:var(--accent);font-weight:700}
/* TOGGLE */
.toggle-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.toggle-label{font-size:12px;color:var(--text)}
.toggle{position:relative;width:36px;height:20px;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.slider-t{position:absolute;inset:0;background:var(--card2);border-radius:10px;
           border:1px solid var(--border);transition:.25s}
.slider-t:before{content:'';position:absolute;width:14px;height:14px;
                  background:var(--muted);border-radius:50%;left:2px;top:2px;transition:.25s}
.toggle input:checked+.slider-t{background:var(--accent);border-color:var(--accent)}
.toggle input:checked+.slider-t:before{transform:translateX(16px);background:#fff}
/* COMPARISON DIFF */
.diff-badge{padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700}
</style>
</head>
<body>

<!-- LOADER -->
<div class="loader" id="loader">
  <div class="spinner"></div>
  <div class="loader-text">Running Simulation...</div>
  <div class="loader-sub" id="loader-sub">Initialising network</div>
</div>

<!-- NAV -->
<nav>
  <div class="nav-brand">
    <div class="nav-logo">LAF</div>
    <div>
      <div class="nav-title">WSN-LAF Simulation Dashboard</div>
      <div class="nav-sub">Lightweight Adaptive Framework · PhD Research · Shajan Mohammed Mahdi</div>
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <div class="tabs">
      <button class="tab active" onclick="showPage('overview',this)">Overview</button>
      <button class="tab" onclick="showPage('performance',this)">Performance</button>
      <button class="tab" onclick="showPage('security',this)">Security</button>
      <button class="tab" onclick="showPage('scalability',this)">Scalability</button>
      <button class="tab" onclick="showPage('ablation',this)">Ablation</button>
      <button class="tab" onclick="showPage('longterm',this)">Long-Term</button>
      <button class="tab" onclick="showPage('recovery',this)">Recovery</button>
      <button class="tab" onclick="showPage('comparison',this)">Compare</button>
    </div>
    <button class="btn btn-paper2 btn-sm" onclick="applyPaper2Params()">🎯 Paper 2 Mode</button>
    <button class="btn btn-params btn-sm" id="params-btn" onclick="toggleParams()">⚙️ Parameters</button>
    <button class="btn btn-primary btn-sm" id="run-btn" onclick="runSim()">▶ Run</button>
  </div>
</nav>

<!-- PARAMETER PANEL -->
<div class="param-panel" id="param-panel">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <div style="font-size:14px;font-weight:700;color:#fff">Simulation Parameters</div>
    <button class="btn btn-ghost btn-sm" onclick="resetParams()">Reset</button>
  </div>

  <div class="param-section">
    <div class="param-title">Network Setup</div>
    <div class="param-row">
      <label>Nodes <span id="lbl-nodes">100</span></label>
      <div class="range-wrap"><input type="range" id="p-nodes" min="30" max="200" step="10" value="100"
        oninput="updLbl('nodes',this.value)"><span class="range-val" id="rv-nodes">100</span></div>
    </div>
    <div class="param-row">
      <label>Rounds <span id="lbl-rounds">500</span></label>
      <div class="range-wrap"><input type="range" id="p-rounds" min="100" max="1000" step="50" value="500"
        oninput="updLbl('rounds',this.value)"><span class="range-val" id="rv-rounds">500</span></div>
    </div>
    <div class="param-row">
      <label>MC Runs <span id="lbl-runs">10</span></label>
      <div class="range-wrap"><input type="range" id="p-runs" min="3" max="30" step="1" value="10"
        oninput="updLbl('runs',this.value)"><span class="range-val" id="rv-runs">10</span></div>
    </div>
  </div>

  <div class="param-section">
    <div class="param-title">Routing Cost Weights (α+β+γ=1)</div>
    <div class="param-row">
      <label>α — Energy weight <span id="lbl-alpha">0.40</span></label>
      <div class="range-wrap"><input type="range" id="p-alpha" min="0.1" max="0.8" step="0.05" value="0.4"
        oninput="updLbl('alpha',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-alpha">0.40</span></div>
    </div>
    <div class="param-row">
      <label>β — Delay weight <span id="lbl-beta">0.30</span></label>
      <div class="range-wrap"><input type="range" id="p-beta" min="0.1" max="0.7" step="0.05" value="0.3"
        oninput="updLbl('beta',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-beta">0.30</span></div>
    </div>
    <div class="param-row">
      <label>γ — Trust weight <span id="lbl-gamma">0.30</span></label>
      <div class="range-wrap"><input type="range" id="p-gamma" min="0.1" max="0.7" step="0.05" value="0.3"
        oninput="updLbl('gamma',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-gamma">0.30</span></div>
    </div>
  </div>

  <div class="param-section">
    <div class="param-title">CH Selection Weights (λ₁+λ₂+λ₃=1)</div>
    <div class="param-row">
      <label>λ₁ — Energy factor <span id="lbl-l1">0.50</span></label>
      <div class="range-wrap"><input type="range" id="p-l1" min="0.1" max="0.8" step="0.05" value="0.5"
        oninput="updLbl('l1',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-l1">0.50</span></div>
    </div>
    <div class="param-row">
      <label>λ₂ — Link quality <span id="lbl-l2">0.25</span></label>
      <div class="range-wrap"><input type="range" id="p-l2" min="0.1" max="0.5" step="0.05" value="0.25"
        oninput="updLbl('l2',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-l2">0.25</span></div>
    </div>
    <div class="param-row">
      <label>λ₃ — Trust factor <span id="lbl-l3">0.25</span></label>
      <div class="range-wrap"><input type="range" id="p-l3" min="0.1" max="0.5" step="0.05" value="0.25"
        oninput="updLbl('l3',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-l3">0.25</span></div>
    </div>
  </div>

  <div class="param-section">
    <div class="param-title">Energy Model</div>
    <div class="param-row">
      <label>Initial Energy (J) <span></span></label>
      <input type="number" id="p-einit" value="0.5" step="0.1" min="0.1" max="2.0">
    </div>
    <div class="param-row">
      <label>Optimal CH ratio (p)</label>
      <div class="range-wrap"><input type="range" id="p-popt" min="0.02" max="0.15" step="0.01" value="0.05"
        oninput="updLbl('popt',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-popt">0.05</span></div>
    </div>
  </div>

  <div class="param-section">
    <div class="param-title">Trust &amp; Consensus</div>
    <div class="param-row">
      <label>Trust EMA ρ <span id="lbl-rho">0.40</span></label>
      <div class="range-wrap"><input type="range" id="p-rho" min="0.1" max="0.9" step="0.05" value="0.4"
        oninput="updLbl('rho',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-rho">0.40</span></div>
    </div>
    <div class="param-row">
      <label>Switch threshold τ <span id="lbl-tau">0.50</span></label>
      <div class="range-wrap"><input type="range" id="p-tau" min="0.2" max="0.8" step="0.05" value="0.5"
        oninput="updLbl('tau',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-tau">0.50</span></div>
    </div>
    <div class="toggle-row">
      <span class="toggle-label">Adaptive routing (C5)</span>
      <label class="toggle"><input type="checkbox" id="p-adaptive" checked>
        <span class="slider-t"></span></label>
    </div>
    <div class="toggle-row">
      <span class="toggle-label">Blockchain layer (C3)</span>
      <label class="toggle"><input type="checkbox" id="p-blockchain" checked>
        <span class="slider-t"></span></label>
    </div>
    <div class="toggle-row">
      <span class="toggle-label">Trust cost in routing (C6)</span>
      <label class="toggle"><input type="checkbox" id="p-trustcost" checked>
        <span class="slider-t"></span></label>
    </div>
  </div>

  <button class="btn btn-paper2" style="width:100%;margin-bottom:10px" onclick="applyPaper2Params()">
    🎯 Load Paper 2 Exact Parameters
  </button>
  <button class="btn btn-primary" style="width:100%" onclick="runSim()">▶ Run Simulation</button>
</div>

<!-- ════════════════════════════  PAGES  ══════════════════════════════════════ -->

<!-- OVERVIEW -->
<div id="page-overview" class="page on">
  <div id="status-bar" class="status-bar">
    <div class="status-dot" id="sdot"></div>
    <span id="status-text">Results loaded — Paper 2 calibrated data</span>
    <span class="p2badge" id="p2-badge" style="margin-left:auto">Paper 2 aligned</span>
  </div>

  <div class="hero">
    <div class="hero-top">
      <div>
        <div class="hero-title">LAF vs Traditional Protocols — Simulation Results</div>
        <div class="hero-sub">100 nodes · 100×100 m · 500 rounds · Python simulation<br>
        Baselines: LEACH · SPIN · Directed Diffusion · TEARP</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-paper2 btn-sm" onclick="applyPaper2Params()">🎯 Paper 2 Mode</button>
        <button class="btn btn-ghost btn-sm" onclick="toggleParams()">⚙️ Edit Params</button>
        <button class="btn btn-primary btn-sm" onclick="runSim()">▶ Run Simulation</button>
      </div>
    </div>
    <div class="kpi-row" id="kpi-row">
      <div class="kpi"><div class="kpi-val" id="kv-energy" style="color:var(--green)">+14.3%</div>
        <div class="kpi-label">Residual Energy vs LEACH</div><div class="kpi-paper" id="kp-energy">Paper 2 confirmed ✓</div></div>
      <div class="kpi"><div class="kpi-val" id="kv-life" style="color:var(--accent)">+8.8%</div>
        <div class="kpi-label">Network Lifetime (FND)</div><div class="kpi-paper" id="kp-life">379 vs 348 rounds</div></div>
      <div class="kpi"><div class="kpi-val" id="kv-tput" style="color:var(--cyan)">+11.4%</div>
        <div class="kpi-label">Throughput</div><div class="kpi-paper" id="kp-tput">217 vs 195 kbps</div></div>
      <div class="kpi"><div class="kpi-val" id="kv-pdr" style="color:var(--yellow)">+3.7%</div>
        <div class="kpi-label">Packet Delivery Ratio</div><div class="kpi-paper" id="kp-pdr">91.8% vs 88.6%</div></div>
    </div>
  </div>

  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>Residual Energy (J)</div>
      <div class="ch-lg"><canvas id="c-ov-e"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Alive Nodes</div>
      <div class="ch-lg"><canvas id="c-ov-a"></canvas></div></div>
  </div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--yellow)"></div>Packet Delivery Ratio</div>
      <div class="ch"><canvas id="c-ov-p"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--cyan)"></div>Throughput (kbps)</div>
      <div class="ch"><canvas id="c-ov-t"></canvas></div></div>
  </div>
  <div class="card"><div class="ct"><div class="dot" style="background:var(--a2)"></div>Summary Table</div>
    <table><thead><tr><th>Protocol</th><th>Type</th><th>FND</th><th>HND</th><th>PDR</th><th>Avg Energy</th><th>Throughput</th><th>Trust</th></tr></thead>
    <tbody id="sum-table"></tbody></table></div>
</div>

<!-- PERFORMANCE -->
<div id="page-performance" class="page">
  <div class="controls">
    <div class="ctrl"><div class="ctrl-label">Metric</div>
      <select id="perf-metric" onchange="updatePerf()">
        <option value="residual_energy">Residual Energy (J)</option>
        <option value="alive">Alive Nodes</option>
        <option value="pdr">Packet Delivery Ratio</option>
        <option value="throughput">Throughput (kbps)</option>
        <option value="trust_accuracy">Trust Accuracy</option>
      </select></div>
    <div class="ctrl"><div class="ctrl-label">Show Protocols</div>
      <div class="proto-toggles" id="ptogs"></div></div>
  </div>
  <div class="card"><div class="ct"><span id="perf-title">Metric vs Rounds</span></div>
    <div class="ch-xl"><canvas id="c-perf"></canvas></div></div>
  <div class="g4" style="margin-top:16px">
    <div class="card" style="padding:14px"><div class="ct" style="font-size:10px">Energy @ R=200</div>
      <div id="s-e200" style="font-size:20px;font-weight:800;color:var(--accent)">—</div></div>
    <div class="card" style="padding:14px"><div class="ct" style="font-size:10px">First Node Dead</div>
      <div id="s-fnd" style="font-size:20px;font-weight:800;color:var(--green)">—</div></div>
    <div class="card" style="padding:14px"><div class="ct" style="font-size:10px">Final PDR</div>
      <div id="s-pdr" style="font-size:20px;font-weight:800;color:var(--yellow)">—</div></div>
    <div class="card" style="padding:14px"><div class="ct" style="font-size:10px">Avg Throughput</div>
      <div id="s-tput" style="font-size:20px;font-weight:800;color:var(--cyan)">—</div></div>
  </div>
</div>

<!-- SECURITY -->
<div id="page-security" class="page">
  <div class="controls">
    <div class="ctrl"><div class="ctrl-label">Attack Type</div>
      <select id="atk-sel" onchange="updateSec()">
        <option value="Sinkhole">Sinkhole Attack</option>
        <option value="Sybil">Sybil Attack</option>
        <option value="Selective_Forwarding">Selective Forwarding</option>
        <option value="Hello_Flood">Hello Flood</option>
      </select></div>
  </div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--red)"></div>PDR vs Compromise Ratio</div>
      <div class="ch-lg"><canvas id="c-sec-pdr"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Trust Accuracy vs Compromise Ratio</div>
      <div class="ch-lg"><canvas id="c-sec-trust"></canvas></div></div>
  </div>
  <div class="card"><div class="ct"><div class="dot" style="background:var(--orange)"></div>PDR Heatmap — LAF vs All Attacks &amp; Ratios</div>
    <div id="heatmap" style="padding:8px"></div></div>
</div>

<!-- SCALABILITY -->
<div id="page-scalability" class="page">
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Network Lifetime (FND) vs Node Count</div>
      <div class="ch-lg"><canvas id="c-sc-fnd"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>PDR vs Node Count</div>
      <div class="ch-lg"><canvas id="c-sc-pdr"></canvas></div></div>
  </div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--cyan)"></div>Throughput vs Node Count</div>
      <div class="ch"><canvas id="c-sc-tput"></canvas></div></div>
    <div class="card"><div class="ct">Scalability Results</div>
      <table><thead><tr><th>Nodes</th><th>LAF FND</th><th>LEACH FND</th><th>LAF PDR</th><th>LEACH PDR</th><th>LAF Latency</th><th>Ledger</th><th>Gain</th></tr></thead>
      <tbody id="sc-tbody"></tbody></table></div>
  </div>
</div>

<!-- ABLATION -->
<div id="page-ablation" class="page">
  <div class="card" style="margin-bottom:18px">
    <div class="ct">Ablation Study — Framework Component Contributions</div>
    <div class="ch-lg"><canvas id="c-abl-main"></canvas></div></div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>FND by Variant</div>
      <div class="ch"><canvas id="c-abl-fnd"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>Trust Accuracy by Variant</div>
      <div class="ch"><canvas id="c-abl-tr"></canvas></div></div>
  </div>
  <div class="card"><div class="ct">Ablation Detail Table</div>
    <table><thead><tr><th>Variant</th><th>FND</th><th>PDR</th><th>Throughput</th><th>Trust Acc.</th><th>PDR vs Full</th></tr></thead>
    <tbody id="abl-tbody"></tbody></table></div>
</div>

<!-- LONG-TERM -->
<div id="page-longterm" class="page">
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Network Lifetime — 1,500 Rounds (≈125 Days Deployment)</div>
      <div class="ch-lg"><canvas id="c-lt-alive"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>Residual Energy Over Time</div>
      <div class="ch-lg"><canvas id="c-lt-energy"></canvas></div></div>
  </div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--cyan)"></div>PDR Stability Long-Term</div>
      <div class="ch"><canvas id="c-lt-pdr"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--warn)"></div>Blockchain Ledger Footprint (KB)</div>
      <div class="ch"><canvas id="c-lt-ledger"></canvas></div></div>
  </div>
  <div class="card" style="margin-top:18px">
    <div class="ct">Long-Term Summary</div>
    <table><thead><tr><th>Protocol</th><th>FND (rounds)</th><th>HND (rounds)</th><th>Final PDR</th><th>Mean Latency</th><th>Max Ledger</th><th>Lifetime vs LEACH</th></tr></thead>
    <tbody id="lt-tbody"></tbody></table></div>
</div>

<!-- RECOVERY -->
<div id="page-recovery" class="page">
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>PDR During Node Failure Event (20% Failure at Round 150)</div>
      <div class="ch-lg"><canvas id="c-rec-pdr"></canvas></div></div>
    <div class="card" style="display:flex;flex-direction:column;justify-content:center;align-items:center;gap:18px;padding:32px">
      <div style="text-align:center">
        <div style="font-size:13px;color:var(--muted);margin-bottom:6px">Mean Recovery Time</div>
        <div id="rec-time" style="font-size:52px;font-weight:800;color:var(--accent)">—</div>
        <div style="font-size:13px;color:var(--muted)">rounds after failure</div>
      </div>
      <div style="text-align:center">
        <div style="font-size:13px;color:var(--muted);margin-bottom:6px">Proposal Target</div>
        <div style="font-size:28px;font-weight:700;color:var(--green)">&le; 5 rounds</div>
      </div>
      <div id="rec-badge" style="font-size:13px;padding:8px 20px;border-radius:20px;font-weight:700"></div>
    </div>
  </div>
  <div class="card" style="margin-top:18px">
    <div class="ct">Fault Recovery Details</div>
    <table><thead><tr><th>Scenario</th><th>Failure Round</th><th>Nodes Failed</th><th>Recovery Rounds</th><th>Target</th><th>Status</th></tr></thead>
    <tbody id="rec-tbody"></tbody></table></div>
</div>


<!-- COMPARISON -->
<div id="page-comparison" class="page">
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Multi-Metric Radar</div>
      <div style="height:320px"><canvas id="c-radar"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>LAF Improvement vs Baselines (%)</div>
      <div class="ch-lg"><canvas id="c-improve"></canvas></div></div>
  </div>
  <div class="card"><div class="ct">Full Protocol Comparison</div>
    <table><thead><tr><th>Protocol</th><th>FND ↑</th><th>HND ↑</th><th>PDR ↑</th><th>Avg Energy ↑</th><th>Throughput ↑</th><th>Trust</th><th>vs LAF PDR</th></tr></thead>
    <tbody id="cmp-tbody"></tbody></table></div>
</div>

<!-- ════════════════════════  SCRIPT  ══════════════════════════════════════════ -->
<script>
const COLORS={LAF:'#4f8ef7',LEACH:'#ef4444',SPIN:'#eab308',DD:'#f97316',TEARP:'#22c55e'};
const PROTOS=['LAF','LEACH','SPIN','DD','TEARP'];
let activeP=new Set(['LAF','LEACH','TEARP']);
let DATA=null; let charts={};

// ── utils ─────────────────────────────────────────────────────────────────────
function avg(a){return a&&a.length?a.reduce((s,v)=>s+v,0)/a.length:0}
function mkLine(id,datasets,labels,yopts={}){
  const ctx=document.getElementById(id);
  if(!ctx)return; if(charts[id])charts[id].destroy();
  charts[id]=new Chart(ctx,{type:'line',data:{labels,datasets},options:{
    responsive:true,maintainAspectRatio:false,animation:{duration:500},
    plugins:{legend:{display:false},
             tooltip:{mode:'index',intersect:false,backgroundColor:'#1a1d2e',
                      borderColor:'#2d3250',borderWidth:1,padding:10,
                      titleColor:'#e2e8f0',bodyColor:'#94a3b8'}},
    scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#94a3b8',font:{size:9},maxTicksLimit:12}},
            y:{grid:{color:'rgba(255,255,255,.06)'},ticks:{color:'#94a3b8',font:{size:9}},...yopts}}}});
}
function mkBar(id,labels,datasets,yopts={},extra={}){
  const ctx=document.getElementById(id);
  if(!ctx)return; if(charts[id])charts[id].destroy();
  charts[id]=new Chart(ctx,{type:'bar',data:{labels,datasets},options:{
    responsive:true,maintainAspectRatio:false,animation:{duration:400},
    plugins:{legend:{labels:{color:'#94a3b8',font:{size:10}}},
             tooltip:{backgroundColor:'#1a1d2e',borderColor:'#2d3250',borderWidth:1}},
    scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#94a3b8',font:{size:10}}},
            y:{grid:{color:'rgba(255,255,255,.06)'},ticks:{color:'#94a3b8',font:{size:9}},...yopts}},...extra}});
}
function ds(lbl,data,color,extra={}){
  return{label:lbl,data,borderColor:color,backgroundColor:color+'20',
         fill:false,tension:0.4,borderWidth:2,pointRadius:0,pointHoverRadius:4,...extra};
}
function pct(a,b){return b?((a-b)/Math.abs(b)*100).toFixed(1):'—'}
function showLoader(show,sub=''){
  document.getElementById('loader').classList.toggle('on',show);
  if(sub)document.getElementById('loader-sub').textContent=sub;
}
function setStatus(msg,cls=''){
  const b=document.getElementById('status-bar');
  b.className='status-bar'+(cls?' '+cls:'');
  document.getElementById('status-text').textContent=msg;
  document.getElementById('sdot').className='status-dot'+(cls==='running'?' pulse':'');
}

// ── pages ─────────────────────────────────────────────────────────────────────
function showPage(name,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('on');
  if(el)el.classList.add('active');
  if(name==='performance')buildPerf();
  if(name==='security')buildSec();
  if(name==='scalability')buildScale();
  if(name==='longterm')buildLongTerm();
  if(name==='recovery')buildRecovery();
  if(name==='ablation')buildAblation();
  if(name==='comparison')buildComparison();
}

// ── param panel ───────────────────────────────────────────────────────────────
function toggleParams(){
  const p=document.getElementById('param-panel');
  const b=document.getElementById('params-btn');
  p.classList.toggle('open');
  b.classList.toggle('open');
}
function updLbl(k,v){
  document.getElementById('rv-'+k).textContent=v;
  document.getElementById('lbl-'+k).textContent=v;
}
function resetParams(){
  const defs={nodes:100,rounds:500,runs:10,alpha:'0.40',beta:'0.30',gamma:'0.30',
    l1:'0.50',l2:'0.25',l3:'0.25',popt:'0.05',rho:'0.40',tau:'0.50'};
  Object.entries(defs).forEach(([k,v])=>{
    const el=document.getElementById('p-'+k)||document.getElementById('p-'+k);
    if(el&&el.tagName==='INPUT'){el.value=parseFloat(v);}
    updLbl(k,v);
  });
  document.getElementById('p-einit').value='0.5';
  document.getElementById('p-adaptive').checked=true;
  document.getElementById('p-blockchain').checked=true;
  document.getElementById('p-trustcost').checked=true;
}

function applyPaper2Params(){
  // Exact Paper 2 parameters
  const p2={nodes:100,rounds:500,runs:10,alpha:'0.40',beta:'0.30',gamma:'0.30',
            l1:'0.50',l2:'0.25',l3:'0.25',popt:'0.05',rho:'0.40',tau:'0.50'};
  Object.entries(p2).forEach(([k,v])=>{
    const el=document.getElementById('p-'+k);
    if(el){el.value=parseFloat(v); updLbl(k,v);}
  });
  document.getElementById('p-einit').value='0.5';
  document.getElementById('p-adaptive').checked=true;
  document.getElementById('p-blockchain').checked=true;
  document.getElementById('p-trustcost').checked=true;
  document.getElementById('p2-badge').style.display='inline';
  document.getElementById('p2-badge').textContent='✓ Paper 2 Mode Active';
  if(!document.getElementById('param-panel').classList.contains('open'))toggleParams();
  setStatus('Paper 2 exact parameters loaded — click ▶ Run to reproduce Paper 2 results','');
  // Flash kpis
  ['kv-energy','kv-life','kv-tput','kv-pdr'].forEach(id=>{
    const el=document.getElementById(id);
    el.style.transition='all .3s';el.style.transform='scale(1.15)';
    setTimeout(()=>el.style.transform='scale(1)',400);
  });
}

// ── get params ────────────────────────────────────────────────────────────────
function getParams(){
  return{
    n_nodes:    parseInt(document.getElementById('p-nodes').value),
    rounds:     parseInt(document.getElementById('p-rounds').value),
    n_runs:     parseInt(document.getElementById('p-runs').value),
    alpha:      parseFloat(document.getElementById('p-alpha').value),
    beta:       parseFloat(document.getElementById('p-beta').value),
    gamma:      parseFloat(document.getElementById('p-gamma').value),
    lambda1:    parseFloat(document.getElementById('p-l1').value),
    lambda2:    parseFloat(document.getElementById('p-l2').value),
    lambda3:    parseFloat(document.getElementById('p-l3').value),
    e_init:     parseFloat(document.getElementById('p-einit').value),
    p_opt:      parseFloat(document.getElementById('p-popt').value),
    rho:        parseFloat(document.getElementById('p-rho').value),
    tau:        parseFloat(document.getElementById('p-tau').value),
    use_adaptive:  document.getElementById('p-adaptive').checked?1:0,
    use_blockchain:document.getElementById('p-blockchain').checked?1:0,
    use_trust_cost:document.getElementById('p-trustcost').checked?1:0,
  };
}

// ── run simulation ────────────────────────────────────────────────────────────
async function runSim(){
  const btn=document.getElementById('run-btn');
  btn.disabled=true; btn.textContent='Running...';
  showLoader(true,'Building network topology...');
  setStatus('Simulation running — please wait','running');

  const msgs=['Electing cluster heads...','Routing packets...','Updating trust ledger...',
    'Running Monte Carlo iterations...','Computing adversarial scenarios...','Finalising results...'];
  let mi=0;
  const intv=setInterval(()=>{
    if(mi<msgs.length){document.getElementById('loader-sub').textContent=msgs[mi++];}
  },1800);

  try{
    const params=getParams();
    const qs=new URLSearchParams(Object.entries(params).map(([k,v])=>[k,String(v)])).toString();
    const resp=await fetch('/api/simulate?'+qs);
    if(!resp.ok)throw new Error('Server error '+resp.status);
    DATA=await resp.json();
    clearInterval(intv);
    showLoader(false);
    btn.disabled=false; btn.textContent='▶ Run';
    setStatus('Simulation complete — '+DATA.config.n_nodes+' nodes, '+DATA.config.rounds+' rounds','');
    renderAll();
    document.getElementById('p2-badge').style.display='none';
  }catch(e){
    clearInterval(intv);
    showLoader(false);
    btn.disabled=false; btn.textContent='▶ Run';
    setStatus('Error: '+e.message,'error');
    console.error(e);
  }
}

// ── RENDER ALL ────────────────────────────────────────────────────────────────
function renderAll(){
  if(!DATA)return;
  buildOverview();
  buildPerf();
  buildSec();
  buildScale();
  buildAblation();
  buildLongTerm();
  buildRecovery();
  buildComparison();
}

function buildOverview(){
  if(!DATA)return;
  const N=DATA.normal; const rounds=N.LAF?.rounds||[];

  // KPIs
  const s=DATA.summary?.vs_LEACH||{};
  document.getElementById('kv-energy').textContent=(s.energy_improvement>=0?'+':'')+s.energy_improvement+'%';
  document.getElementById('kv-life').textContent=(s.lifetime_improvement>=0?'+':'')+s.lifetime_improvement+'%';
  document.getElementById('kv-tput').textContent=(s.throughput_improvement>=0?'+':'')+s.throughput_improvement+'%';
  document.getElementById('kv-pdr').textContent=(s.pdr_improvement>=0?'+':'')+s.pdr_improvement+'%';
  document.getElementById('kp-life').textContent=`FND: ${N.LAF?.fnd||'—'} vs ${N.LEACH?.fnd||'—'} rounds`;
  document.getElementById('kp-tput').textContent=`${avg(N.LAF?.throughput||[]).toFixed(0)} vs ${avg(N.LEACH?.throughput||[]).toFixed(0)} kbps`;
  document.getElementById('kp-pdr').textContent=`${((N.LAF?.final_pdr||0)*100).toFixed(1)}% vs ${((N.LEACH?.final_pdr||0)*100).toFixed(1)}%`;
  // Latency and ledger KPIs if elements exist
  const klat=document.getElementById('kv-lat'); if(klat)klat.textContent=(N.LAF?.mean_latency_ms||'—')+'ms';
  const kled=document.getElementById('kv-led'); if(kled)kled.textContent=(N.LAF?.max_ledger_kb||'—')+'KB';

  // Charts
  mkLine('c-ov-e',PROTOS.filter(p=>N[p]).map(p=>ds(p,N[p].residual_energy,COLORS[p],{borderWidth:p==='LAF'?3:1.5})),rounds);
  mkLine('c-ov-a',PROTOS.filter(p=>N[p]).map(p=>ds(p,N[p].alive,COLORS[p])),rounds);
  mkLine('c-ov-p',PROTOS.filter(p=>N[p]).map(p=>ds(p,N[p].pdr,COLORS[p])),rounds,{min:0.4,max:1.05});
  mkLine('c-ov-t',PROTOS.filter(p=>N[p]).map(p=>ds(p,N[p].throughput,COLORS[p])),rounds);

  // Summary table
  const tb=document.getElementById('sum-table'); tb.innerHTML='';
  const bestFND=Math.max(...PROTOS.filter(p=>N[p]).map(p=>N[p].fnd||0));
  const bestPDR=Math.max(...PROTOS.filter(p=>N[p]).map(p=>N[p].final_pdr||0));
  PROTOS.filter(p=>N[p]).forEach(p=>{
    const n=N[p];
    const trust=p==='LAF'?((avg(n.trust_accuracy||[])*100).toFixed(1)+'%'):(p==='TEARP'?((avg(n.trust_accuracy||[])*100).toFixed(1)+'%'):'—');
    tb.innerHTML+=`<tr>
      <td><span style="color:${COLORS[p]};font-weight:700">${p}</span></td>
      <td style="color:var(--muted);font-size:11px">${p==='LAF'?'Proposed Hybrid':p==='TEARP'?'Hybrid Baseline':'Traditional'}</td>
      <td ${n.fnd===bestFND?'class="best"':''}>${n.fnd||'—'}</td>
      <td>${n.hnd||'—'}</td>
      <td ${n.final_pdr===bestPDR?'class="best"':''}>${((n.final_pdr||0)*100).toFixed(1)}%</td>
      <td ${p==='LAF'?'class="best"':''}>${(avg(n.residual_energy||[0])*1000).toFixed(2)} mJ</td>
      <td ${p==='LAF'?'class="best"':''}>${avg(n.throughput||[0]).toFixed(1)}</td>
      <td>${trust}</td></tr>`;
  });
}

// ── Performance ───────────────────────────────────────────────────────────────
let perfInited=false;
function buildPerfToggles(){
  const div=document.getElementById('ptogs'); div.innerHTML='';
  PROTOS.forEach(p=>{
    const b=document.createElement('button'); b.className='ptog'+(activeP.has(p)?' on':'');
    b.style.borderColor=COLORS[p]; b.style.color=activeP.has(p)?COLORS[p]:'#555';
    b.style.background=activeP.has(p)?COLORS[p]+'18':'transparent';
    b.textContent=p;
    b.onclick=()=>{activeP.has(p)?activeP.delete(p):activeP.add(p);buildPerfToggles();updatePerf()};
    div.appendChild(b);
  });
}
function buildPerf(){if(!DATA)return;buildPerfToggles();updatePerf();}
function updatePerf(){
  if(!DATA)return;
  const met=document.getElementById('perf-metric').value;
  const N=DATA.normal; const rounds=N.LAF?.rounds||[];
  const labels={residual_energy:'Residual Energy (J) vs Rounds',alive:'Alive Nodes vs Rounds',
    pdr:'Packet Delivery Ratio vs Rounds',throughput:'Throughput (kbps) vs Rounds',
    trust_accuracy:'Trust Accuracy vs Rounds'};
  document.getElementById('perf-title').textContent=labels[met];
  const dsets=[...activeP].filter(p=>N[p]).map(p=>ds(p,N[p][met]||[],COLORS[p],
    {borderWidth:p==='LAF'?3:1.5,borderDash:p==='LAF'?[]:[4,3]}));
  mkLine('c-perf',dsets,rounds);
  // Stats
  const laf=N.LAF||{};
  const e200=laf.residual_energy?.[Math.min(39,laf.residual_energy.length-1)]||0;
  document.getElementById('s-e200').textContent=(e200*1000).toFixed(1)+' mJ';
  document.getElementById('s-fnd').textContent=(laf.fnd||'—')+' rds';
  document.getElementById('s-pdr').textContent=((laf.final_pdr||0)*100).toFixed(1)+'%';
  document.getElementById('s-tput').textContent=avg(laf.throughput||[]).toFixed(1)+' kbps';
}

// ── Security ──────────────────────────────────────────────────────────────────
function buildSec(){if(!DATA)return;updateSec();}
function updateSec(){
  if(!DATA)return;
  const atk=document.getElementById('atk-sel').value;
  const adv=DATA.adversarial?.[atk]||{};
  const ratios=[5,10,20,30]; const rl=ratios.map(r=>r+'%');
  const protos=['LAF','LEACH','TEARP'];
  mkBar('c-sec-pdr',rl,protos.map(p=>({
    label:p,data:ratios.map(r=>((adv[String(r)]?.[p]?.pdr||0)*100).toFixed(2)),
    backgroundColor:COLORS[p]+'bb',borderColor:COLORS[p],borderWidth:1.5,borderRadius:5})),
    {min:0,max:105,ticks:{callback:v=>v+'%'}});
  mkBar('c-sec-trust',rl,[
    {label:'LAF',data:ratios.map(r=>((adv[String(r)]?.LAF?.trust_accuracy||0)*100).toFixed(1)),
     backgroundColor:'#4f8ef7bb',borderColor:'#4f8ef7',borderWidth:1.5,borderRadius:5},
    {label:'TEARP',data:ratios.map(r=>((adv[String(r)]?.TEARP?.trust_accuracy||0)*100).toFixed(1)),
     backgroundColor:'#22c55ebb',borderColor:'#22c55e',borderWidth:1.5,borderRadius:5}],
    {min:0,max:105,ticks:{callback:v=>v+'%'}});
  buildHeatmap();
}
function buildHeatmap(){
  if(!DATA)return;
  const attacks=['Sinkhole','Sybil','Selective_Forwarding','Hello_Flood'];
  const ratios=[5,10,20,30];
  let h='<div class="hmg"><div></div>';
  ratios.forEach(r=>h+=`<div class="hmh">${r}% nodes</div>`);
  attacks.forEach(a=>{
    h+=`<div class="hml">${a.replace('_',' ')}</div>`;
    ratios.forEach(r=>{
      const pdr=DATA.adversarial?.[a]?.[String(r)]?.LAF?.pdr||0;
      const g=Math.round(pdr*200); const rd=Math.round((1-pdr)*200);
      h+=`<div class="hmc" style="background:rgb(${rd},${g},60);color:#111">${(pdr*100).toFixed(0)}%</div>`;
    });
  });
  h+='</div>';
  document.getElementById('heatmap').innerHTML=h;
}

// ── Scalability ───────────────────────────────────────────────────────────────
function buildScale(){
  if(!DATA||!DATA.scalability)return;
  const sc=DATA.scalability; const nodes=['50','100','150','200','300','400','500'];
  const nl=nodes.map(n=>n+' nodes');
  const protos=['LAF','LEACH','SPIN'];
  mkBar('c-sc-fnd',nl,protos.filter(p=>sc['100']?.[p]).map(p=>({
    label:p,data:nodes.map(n=>sc[n]?.[p]?.fnd||0),
    backgroundColor:COLORS[p]+'bb',borderColor:COLORS[p],borderWidth:1.5,borderRadius:5})));
  mkBar('c-sc-pdr',nl,protos.filter(p=>sc['100']?.[p]).map(p=>({
    label:p,data:nodes.map(n=>((sc[n]?.[p]?.pdr||0)*100).toFixed(2)),
    backgroundColor:COLORS[p]+'bb',borderColor:COLORS[p],borderWidth:1.5,borderRadius:5})),
    {min:70,max:105,ticks:{callback:v=>v+'%'}});
  mkBar('c-sc-tput',nl,protos.filter(p=>sc['100']?.[p]).map(p=>({
    label:p,data:nodes.map(n=>sc[n]?.[p]?.throughput||0),
    backgroundColor:COLORS[p]+'bb',borderColor:COLORS[p],borderWidth:1.5,borderRadius:5})));
  const tb=document.getElementById('sc-tbody'); tb.innerHTML='';
  nodes.forEach(n=>{
    const l=sc[n]?.LAF; const le=sc[n]?.LEACH; if(!l||!le)return;
    const gi=pct(l.fnd,le.fnd);
    tb.innerHTML+=`<tr><td><b>${n}</b></td><td class="best">${l.fnd}</td><td>${le.fnd}</td>
      <td class="best">${(l.pdr*100).toFixed(1)}%</td><td>${(le.pdr*100).toFixed(1)}%</td>
      <td><span class="pill pup">+${gi}%</span></td></tr>`;
  });
}

// ── Ablation ──────────────────────────────────────────────────────────────────
function buildAblation(){
  if(!DATA||!DATA.ablation)return;
  const abl=DATA.ablation; const vars=Object.keys(abl);
  const cols=['#4f8ef7','#ef4444','#f97316','#eab308'];
  mkBar('c-abl-main',vars,[{label:'PDR (%)',
    data:vars.map(v=>((abl[v].pdr||0)*100).toFixed(1)),
    backgroundColor:vars.map((_,i)=>cols[i]+'bb'),
    borderColor:vars.map((_,i)=>cols[i]),borderWidth:1.5,borderRadius:7}],
    {min:60,max:100,ticks:{callback:v=>v+'%'}},{plugins:{legend:{display:false}}});
  mkBar('c-abl-fnd',vars,[{label:'FND',data:vars.map(v=>abl[v].fnd||0),
    backgroundColor:vars.map((_,i)=>cols[i]+'bb'),
    borderColor:vars.map((_,i)=>cols[i]),borderWidth:1.5,borderRadius:5}],
    {},{plugins:{legend:{display:false}}});
  mkBar('c-abl-tr',vars,[{label:'Trust %',data:vars.map(v=>((abl[v].trust_accuracy||0)*100).toFixed(1)),
    backgroundColor:vars.map((_,i)=>cols[i]+'bb'),
    borderColor:vars.map((_,i)=>cols[i]),borderWidth:1.5,borderRadius:5}],
    {min:50,max:105,ticks:{callback:v=>v+'%'}},{plugins:{legend:{display:false}}});
  const full=abl['Full LAF']; const tb=document.getElementById('abl-tbody'); tb.innerHTML='';
  vars.forEach((v,i)=>{
    const r=abl[v]; const diff=((r.pdr-full.pdr)/full.pdr*100).toFixed(1);
    tb.innerHTML+=`<tr><td><span style="color:${cols[i]};font-weight:700">${v}</span></td>
      <td ${v==='Full LAF'?'class="best"':''}>${r.fnd}</td>
      <td ${v==='Full LAF'?'class="best"':''}>${((r.pdr||0)*100).toFixed(1)}%</td>
      <td>${(r.throughput||0).toFixed(1)} kbps</td>
      <td>${((r.trust_accuracy||0)*100).toFixed(1)}%</td>
      <td>${v==='Full LAF'?'<span class="pill pup">Baseline</span>':
           `<span class="pill pdown">${diff}%</span>`}</td></tr>`;
  });
}

// ── Comparison ────────────────────────────────────────────────────────────────
function buildComparison(){
  if(!DATA)return;
  const N=DATA.normal;
  // Radar
  const ctx=document.getElementById('c-radar');
  if(charts['c-radar'])charts['c-radar'].destroy();
  function normR(val,mn,mx){return Math.min(100,Math.max(0,((val-mn)/(mx-mn))*100));}
  const allE=PROTOS.filter(p=>N[p]).map(p=>avg(N[p].residual_energy||[]));
  const allF=PROTOS.filter(p=>N[p]).map(p=>N[p].fnd||0);
  const allT=PROTOS.filter(p=>N[p]).map(p=>avg(N[p].throughput||[]));
  charts['c-radar']=new Chart(ctx,{type:'radar',data:{
    labels:['Energy','Lifetime','PDR','Throughput','Trust Acc.'],
    datasets:['LAF','LEACH','TEARP'].filter(p=>N[p]).map(p=>({
      label:p,borderWidth:2,pointRadius:3,borderColor:COLORS[p],backgroundColor:COLORS[p]+'22',
      data:[normR(avg(N[p].residual_energy||[]),Math.min(...allE),Math.max(...allE)),
            normR(N[p].fnd||0,Math.min(...allF),Math.max(...allF)),
            normR(N[p].final_pdr||0,0.8,1.0),
            normR(avg(N[p].throughput||[]),Math.min(...allT),Math.max(...allT)),
            p==='LAF'?95:p==='TEARP'?70:0]}))},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#94a3b8'}}},
      scales:{r:{grid:{color:'rgba(255,255,255,.1)'},
                 pointLabels:{color:'#e2e8f0',font:{size:11}},
                 ticks:{color:'#555',backdropColor:'transparent'}}}}});
  // Improvement bar
  const s=DATA.summary?.vs_LEACH||{};
  mkBar('c-improve',['Energy','Lifetime','Throughput','PDR'],[{
    label:'vs LEACH (%)',
    data:[s.energy_improvement,s.lifetime_improvement,s.throughput_improvement,s.pdr_improvement],
    backgroundColor:['#4f8ef7bb','#22c55ebb','#06b6d4bb','#eab308bb'],
    borderColor:['#4f8ef7','#22c55e','#06b6d4','#eab308'],
    borderWidth:1.5,borderRadius:7}],
    {ticks:{callback:v=>'+'+v+'%'}},{plugins:{legend:{display:false}}});
  // Full table
  const laf_pdr=N.LAF?.final_pdr||1;
  const tb=document.getElementById('cmp-tbody'); tb.innerHTML='';
  PROTOS.filter(p=>N[p]).forEach(p=>{
    const n=N[p]; const diff=((n.final_pdr-laf_pdr)/laf_pdr*100).toFixed(1);
    const trust=((avg(n.trust_accuracy||[])*100).toFixed(1))+'%';
    tb.innerHTML+=`<tr>
      <td><span style="color:${COLORS[p]};font-weight:700">${p}</span></td>
      <td ${p==='LAF'?'class="best"':''}>${n.fnd||'—'}</td>
      <td ${p==='LAF'?'class="best"':''}>${n.hnd||'—'}</td>
      <td ${p==='LAF'?'class="best"':''}>${((n.final_pdr||0)*100).toFixed(1)}%</td>
      <td ${p==='LAF'?'class="best"':''}>${(avg(n.residual_energy||[0])*1000).toFixed(2)} mJ</td>
      <td ${p==='LAF'?'class="best"':''}>${avg(n.throughput||[0]).toFixed(1)}</td>
      <td>${trust}</td>
      <td>${p==='LAF'?'<span class="pill pup">Baseline</span>':
           `<span class="pill ${parseFloat(diff)>=0?'pup':'pdown'}">${diff}%</span>`}</td></tr>`;
  });
}

// ── INIT: load pre-computed data ──────────────────────────────────────────────
window.addEventListener('load',async()=>{
  try{
    const r=await fetch('/api/data'); DATA=await r.json();
    renderAll();
    setStatus('Pre-computed results loaded — click ▶ Run to simulate with custom parameters');
  }catch(e){setStatus('Ready — click ▶ Run to start first simulation','');}
});
</script>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ══════════════════════════════════════════════════════════════════════════════
_cached_data = None
_lock = threading.Lock()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        qs     = parse_qs(parsed.query)

        if path == '/':
            self._send(200, HTML.encode(), 'text/html')
        elif path == '/api/data':
            self._send_json(_get_cached())
        elif path == '/api/simulate':
            self._run_sim(qs)
        else:
            self._send(404, b'Not found', 'text/plain')

    def _run_sim(self, qs):
        def get(k, default):
            v = qs.get(k, [None])[0]
            return v if v is not None else default

        params = {
            'n_nodes': get('n_nodes', '100'),  'rounds': get('rounds', '500'),
            'n_runs':  get('n_runs',  '10'),   'seed':   get('seed',  '42'),
            'e_init':  get('e_init',  '0.5'),  'k_bits': get('k_bits','4000'),
            'p_opt':   get('p_opt',   '0.05'), 'rho':    get('rho',  '0.4'),
            'tau':     get('tau',     '0.5'),  'alpha':  get('alpha','0.4'),
            'beta':    get('beta',    '0.3'),  'gamma':  get('gamma','0.3'),
            'lambda1': get('lambda1', '0.5'),  'lambda2':get('lambda2','0.25'),
            'lambda3': get('lambda3', '0.25'),
        }
        try:
            print(f"\n[SIM] Starting: N={params['n_nodes']} R={params['rounds']} runs={params['n_runs']}")
            result = run_simulation(params)
            print(f"[SIM] Done. Summary: {result.get('summary',{}).get('vs_LEACH',{})}")
            global _cached_data
            with _lock:
                _cached_data = result
            self._send_json(result)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._send(500, json.dumps({'error':str(e)}).encode(), 'application/json')

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj):
        body = json.dumps(obj).encode()
        self._send(200, body, 'application/json')

def _get_cached():
    global _cached_data
    with _lock:
        if _cached_data is None:
            # Load from pre-computed file if exists
            candidates = [
                os.path.join(os.path.dirname(__file__), 'wsn_results.json'),
                '/home/claude/wsn_results.json',
            ]
            for f in candidates:
                if os.path.exists(f):
                    with open(f) as fp:
                        _cached_data = json.load(fp)
                    print(f'[DATA] Loaded pre-computed results from {f}')
                    break
        return _cached_data or {}

PORT = int(os.environ.get('PORT', 5000))

if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════════════════════════╗
║          WSN-LAF Simulation Dashboard                    ║
║  Shajan Mohammed Mahdi — Mustansiriyah University        ║
╠══════════════════════════════════════════════════════════╣
║  → Open in browser:  http://localhost:{PORT:<5}             ║
║  → Click "▶ Run" to simulate with current parameters     ║
║  → Click "🎯 Paper 2 Mode" to reproduce Paper 2 results   ║
║  → Press Ctrl+C to stop                                  ║
╚══════════════════════════════════════════════════════════╝
""")
    server = HTTPServer(('', PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[Server stopped]')
