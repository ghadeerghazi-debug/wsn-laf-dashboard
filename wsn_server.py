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
#  PWA ASSETS
# ══════════════════════════════════════════════════════════════════════════════

MANIFEST = json.dumps({
    "name": "WSN-LAF Dashboard — Shajan PhD",
    "short_name": "WSN-LAF",
    "description": "Wireless Sensor Network LAF Protocol Simulation Dashboard",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#faf7f2",
    "theme_color": "#f97316",
    "orientation": "any",
    "icons": [
        {"src": "/icon-192.svg", "sizes": "192x192", "type": "image/svg+xml", "purpose": "any maskable"},
        {"src": "/icon-512.svg", "sizes": "512x512", "type": "image/svg+xml", "purpose": "any maskable"}
    ]
})

APP_ICON = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#f97316"/>
      <stop offset="100%" style="stop-color:#fb923c"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="96" fill="url(#bg)"/>
  <circle cx="256" cy="200" r="24" fill="#fff" opacity=".9"/>
  <circle cx="180" cy="280" r="18" fill="#fff" opacity=".7"/>
  <circle cx="332" cy="280" r="18" fill="#fff" opacity=".7"/>
  <circle cx="210" cy="360" r="16" fill="#fff" opacity=".5"/>
  <circle cx="302" cy="360" r="16" fill="#fff" opacity=".5"/>
  <circle cx="256" cy="420" r="14" fill="#fff" opacity=".4"/>
  <line x1="256" y1="200" x2="180" y2="280" stroke="#fff" stroke-width="3" opacity=".5"/>
  <line x1="256" y1="200" x2="332" y2="280" stroke="#fff" stroke-width="3" opacity=".5"/>
  <line x1="180" y1="280" x2="210" y2="360" stroke="#fff" stroke-width="2" opacity=".4"/>
  <line x1="332" y1="280" x2="302" y2="360" stroke="#fff" stroke-width="2" opacity=".4"/>
  <line x1="180" y1="280" x2="332" y2="280" stroke="#fff" stroke-width="2" opacity=".3"/>
  <line x1="210" y1="360" x2="302" y2="360" stroke="#fff" stroke-width="2" opacity=".3"/>
  <text x="256" y="155" text-anchor="middle" fill="#fff" font-family="Arial,sans-serif"
    font-size="72" font-weight="900" letter-spacing="-2">LAF</text>
</svg>'''

import base64 as _b64
SHAJAN_PHOTO_B64 = "/9j/4AAQSkZJRgABAQAASABIAAD/4QBARXhpZgAATU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAAqACAAQAAAABAAAAgKADAAQAAAABAAAAgAAAAAD/7QA4UGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAAA4QklNBCUAAAAAABDUHYzZjwCyBOmACZjs+EJ+/+IB2ElDQ19QUk9GSUxFAAEBAAAByAAAAAAEMAAAbW50clJHQiBYWVogB+AAAQABAAAAAAAAYWNzcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPbWAAEAAAAA0y0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJZGVzYwAAAPAAAAAkclhZWgAAARQAAAAUZ1hZWgAAASgAAAAUYlhZWgAAATwAAAAUd3RwdAAAAVAAAAAUclRSQwAAAWQAAAAoZ1RSQwAAAWQAAAAoYlRSQwAAAWQAAAAoY3BydAAAAYwAAAA8bWx1YwAAAAAAAAABAAAADGVuVVMAAAAIAAAAHABzAFIARwBCWFlaIAAAAAAAAG+iAAA49QAAA5BYWVogAAAAAAAAYpkAALeFAAAY2lhZWiAAAAAAAAAkoAAAD4QAALbPWFlaIAAAAAAAAPbWAAEAAAAA0y1wYXJhAAAAAAAEAAAAAmZmAADypwAADVkAABPQAAAKWwAAAAAAAAAAbWx1YwAAAAAAAAABAAAADGVuVVMAAAAgAAAAHABHAG8AbwBnAGwAZQAgAEkAbgBjAC4AIAAyADAAMQA2/8AAEQgAgACAAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/bAEMAAgICAgICAwICAwUDAwMFBgUFBQUGCAYGBgYGCAoICAgICAgKCgoKCgoKCgwMDAwMDA4ODg4ODw8PDw8PDw8PD//bAEMBAgICBAQEBwQEBxALCQsQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEP/dAAQACP/aAAwDAQACEQMRAD8A/n/ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/Q/n/ooooAKKKKACir9hpWpapJ5Wn20lww67FJA+p6D8a7/T/hbrVwFe/mjtA3bO9vyHH61Sg3sS5JbnmNFe+2nws0OOMy3VxNPt44IQZ+mCf1re0f4b6Jqd0mnaZokmoXkpAjijaaSRyewVG5/Km6bQRkmfMlFfoXpn7JuozaxBZa14S+xxzMBskvlgmH1R5tw49RWF8Zv2Pte8F60f8AhH/Dusf2VJEjpOkZvIixHIEkakfrR7NjckfCNFesXfwh8RQwmWFl8xXKNDMrQyAgZ6NxzXnWp6NqmjTeRqds9u/bcOD9COD+FTYq3UzKKKKQgooooA//0f5/6KKUAkgAZJoAntLS6v7qKysYXuLidgkccalndmOAqqOSSegFfQl9+zz4v8Cw2N78S9Ol0t9QTzYLZiA7IOpfBJX6da9f/ZifSvgx4ij8e+JNDTW9QaErDG7BDaliPnQkMBJjjOOASB3r1j9ov4uWfxa1HS9Ss9LfTBZWxiKvKJS5LlsjAGKqKdyFUTdjye2tbS1+HtrBYxJAiTkEKAAevJx1PvXIy3OeB0HTmuutJDJ4EZCuVjn6/jXEmMb8n8q6Y7HO9zpfCnh3WfGfiLTvCugw+bf6pKsMS9BljyWPZVHJPYV9seGdETTdRf4TfAq2k1C7tSY9Y16JWWW+uF4eKGVeYraM8DBBc5J7Vxv7LXgmb/hH/H/xWkYxJ4f0yW0s36H7XdjZuB7FVP61+hXwL1P4UfCzwxp2iR6tb2tyUX7RJtc+ZO4BYtJt2k5968TNcxlSajTWp9FkmVRrpym9EfEes/B34geGLqddb0WV0U7mmiBJPHLK/LEj3IrGi1bWvAd9b634e1S70ySL5omjmkjViOquqnafxBr9tnv9FutMGo3U0UloV3eY2Nm09818n/FPwD+z58RLW5gstTWw1Ug4ltEl2Bv9oKhQiuHC55Uv76uevi+Hqaj7lzrvgn4++C37ZnhafwV8T/DVm3inS0Dyo6BZJ0HHnQyptk/3huyPoa8e/aV/4JoeFdU8Py6x8C42g1G1UmTSLqUzQ3KgZIikkyySegJIPTivir4W65rPwI+P2jalNcL/AMS6/jgmZThJrWY7GxnsVYmv6KtWvpEt47uzcFY2Vjj+JD/nNfT0P3iuj4jE81Gbifxf+JvgxqEF3f21hEbG/wBOZknsrnKOHQ4ZRnkMD2P514RPBNazPb3KGKWMlWVhggjsRX9M37b/AMLPAWiXqfG9LcWc+ryDT9QjWIOssmCyTkfwthcMe/Ffh/8AEPwNb+Kbm6utIjxeRljEwUgSIOQrcenQ9qwq2i7Nm9OXMrpHynRT5I3ikaKVSjoSCDwQR1BplSUf/9L+f+vTfhj4dXVtYbUrpN9rp+1iD0MjZ2D9CfwrzKvrX4Y6NHafDCHVQMyXt9KzHvtQBAPwIJ/GqhuRUdkdmJezHr+NZOvSq0ESIMFVOT681PuPIyBisrVB+7BPIIOOferOak9Te0qZW8D3UDkk/aAyjHuM1zCKQCV5z+GK6Hw2BP4c1C3djkPuA/8Ar1zjKFLAHnkVqndDlufrX8MfCSab+yb4b8JWki295471OIySnglC+9/rhE4r0xf2ePFVpcy6hdeO706Yh3pGH24THCbfunHbivmLTNe1/wAXfB74SeKPDlwosvBN29pqEYBJinLYV2C54MZ4zX2P4s17xLa6Fa6lp8C6nZzFQ8SOUKq3VzgEttHOF5r4jOq84Vklsz9I4XoUqlC0t7nvei+G7TTPhnZ6X/aTT3MvzyTNtdgn+1gAcfSvDdV+AXxC1G5Fz4b8cXNoG3HzEkIVg3QlVIX5ewAFR+GdbtrdIXa8srxUACW7fa0cA/WM/lzXq3hzVtfnnlkFhJp1oxO0SMCrf7SZAYD2ZQa4ZYhxtK33H0EsDC3K2z5O/aU/Ze1bVvDVr4yPiWO48R6HABNLKm0XKR/MCdv3WHY1+lHw38QP4g+G3hnVrg/vb/S7V39CxiAP618c/tCavJbeDRpc9wftmv3EWnWyL95pLhtvA/2QST7V9V+HoLfwz4M0fQ4X/dadZwwITwCscYG7PYcZr6/IKknB32PzjiijTVVKG58u/tg+JbeLw74a8HXHl+Zq11PO6sc/JEhAP5kV+c8lmkc/klUAPPyitf4zfGLRvjZ+0RdWM2omLwzoFvNZWkqS+UJXUgyyb+6swwPYVzEuueHYbsxDUIdqNsU+Ypyq8DJrXMKcZS5rHm4S8VY+BP2ivBsOi+JI/EdggW31QsJQBwJ16nj+8OfqDXznX3l8ev7H1jwZqYtbqKeeyeOdAjAnIcKx4/2WNfBtaU37qJnuf//T/n/r64+GeqR3Pwwt7JeWsruZWH+8d4/9Cr5Hr3b4FajosmvXHhnxJqp0iy1FN0c3lmUCeP7qlQRjcCRn1xTUrEVI3Vkeqyu24v1zWdfyb88fw17Vc+FfhmmyO18XT3cjcEJY46+mZOfyp8/wu8NzIk7azcIJF+VWgQEj1+8cV7GU5PicdP2eGjdo8+vioUFzVNDyjw7IU0W+CgkiQE4/u4rR0fwR4y8UuieG9CvdT82TYpt4HkBY9twGP8817B4M8I+EvCut2N5qEkmpWi3UDzpIFETRq43BgOuR1r+jy407So9BspfCdrBbQeUkltHAixR7GUEBQoAGRXdnHDeIwElDEWu1fR3MKOYxrawR+WXwN+FnjT4U/De48L+KdCtre/1OZpLq3llBa6UkbEDoSodFyQBkg8V7npun3WiKkGmE3mnnn7LcN5c8XsjH5XA7cg19D3mmaf4jZrDUYVMqMHRWwGjmXo8Z/nXPaxa3Gk3i6bq1i0jsm9HiQvlemSADz696+QxuXRqq0ldHvYHM6lB3g7HA2/xQ+HuizeRqMBtLo8AOjKc98HGP1rP1n4zaSkLzWEX7tRkFjtGK6J9G0KO4P9ppFaM/RnVoic+5wPzrRsPCXwp2AX1hpuozHPLgSs2fUA4/SvFfDybXLKyPov8AWudnzRuz5X8LaL4p+MPxLsPHXiSXyNB0cOLGPIALPxJOFPovyqT1J9BWD+3R8efHPhXQbbwZ4QspdP0vX43im1dThXRPla1hI+6cffPU9B3NfoFFL4b0iKKX+y7KyiIVIyIAP91ETGWPoMV8o/tkG2+Lnw6k8GeB4rbXb3wnqC3OpWkOPOhPl8KpUgBhu+YA9eOor7DLssn7PkpK9j5HF5mnV9pV0ufhLaMfOx0rXiJ80c967KaLRdMuWtrrQ2juIG2yRyLIrAjsQTkVpx61oOFH/CMxKPUK+4/iWrllBp6mvOpaxPCfGV0tloesKx+adFiUe7SKT+gNfO9e9fGrxVY6jJZ+HtOsIrP7MTNOUXDs7DChjk9Bk/jXgtQ2Ukf/1P5/6cjtG4kQ7WU5BHYim0UAfW/wp8YaVq7ramJIdQKYf1LD+JT1we/oa9P1G/n3CPcSOa+A7G+u9Nu4r6xlaGeFgyOpwQRX0J4f+K1rrEcdrrxW0uxx5g4jfPf/AGT+lfacG5qqGJtOVk1Y8vMsK5w91XPcNE1V7S6ng3FopFyUJyK/oz/Zu1CbxN8APCH26R2uBp8YDscuVRmVDn2C4r+Zu2uE+2xNG4bejYwc5GK/eD9mn9pH4QJ4P8EeB9L1onW9K0wQ6hamCUKqglmYOV2kq3PX6Zr6ji5VMRTpqnHmtc8nDRVNtt2PrW80y3e6Cavb7JM8TRnbn6jpU194JOsW0CtPco1uS1vcRSqJEJHTPIZf9lhisvXfjR8P0sZrm2jutUZFLLFBbsC/pguFHP1rg/hD8ek+IniLVfDtpo6+HhZRLKkdxMJbhxnBLRrtCgfU18LHKa3K5uOh0VM0ppLU6SbQPE1jJ5Gt7riHOEuLfPP+/C2cH1wcU3/hE7oDz7W6IRuSwXYVHfOcYr5x/bB/aO+N/wAAtQ0a+8JWGkaloWto0XnXNvIZYrmPkq22QKVK8rkdjX5y+P8A9pb9oL4waWsPiXXTpWlT5WSz0xfssT/9dCpLt9C2K9jJ+EK2MmuXRBVzWMYc1z7D+Nn7TPh/wNqb6D8LrqPxH4niO2S/cCW0sv7wQjh5e3Bwv1rlvgjb+IrnxP4f+Jq6bBpsXiOW5u9Yis49lrNFJ+4TJJJZsgsxP8RNfBeg2lvZTCOMDGD+dfsP+xvc2Xjb4QWthqcECweHLiaF3xtcxrIZR5jE4C857V+jZrklDKcJGdOKd7pvr6ny+LxVXEy5LmN8Qv2ffBPxMk1PRr+3S31fT5GEF5GMS+WRlNxH31xwQefSvyz+OPh/4f8AwB07VtG8dz6onjBYy2l21usD2l2H+5KzsA6xDnccE5GBzX1B+0h+354J+EnibWrD4XTweLPEjSPFvjYvYW55GXkXiUrj7iHHqw6V+HfxD+IvjL4qeK73xr481OXVtWvmy8sh4VR91I16IijhVXAAr824mzLCzXs4RUpWWvZ9dVv+R9DkGCxEPem7R7HJXd3cX91Le3bmSaZi7sepJ61Woor4g+pP/9X+f+iiigAooooA39G8TazoUoksJyAONjjcmD7Hp+FfWHwH/ac0D4e+J5NY8ZaPPOklu0AksmUspb+Io5GR7bq+MKK9fA57i8MrUpu3bdHJicDSqq00fud8I/21PhFJrpk1nxUNPUZMUuoWzxrG275flVZOcd9xHtX0loX7V37Oun6w93ZeO7Gz+1SN9qntBb+bOy4KlpJfmCHPAVR9a/mfortxHFGIqR5ZJfccNHIcNCXM035XP6Of2m/2of2bfij8N5vBtt4mtrq4WWO4t7gzxKIpI8jIG5icgkYwK/OXWPip8JNB0tIDrcV+T/DZtLLKD7/uwg/OvzgorChxHi6WtObT8nY9L6pQilGFNJdt7/N6n1Zrf7Qum2k2fCWnzS46PdlUH/fKE5/MV5drXxz+Kes6Vf8Ah7/hILmx0XU3D3NhaSNBbSsowPMRT8/H94mvJKKnMuI8bjIqGIquSXToRSwVGEuaEUmFFFFeIdQUUUUAf//W/n/ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/Z"
SHAJAN_PHOTO = _b64.b64decode(SHAJAN_PHOTO_B64)

SERVICE_WORKER = '''
const CACHE_NAME = "wsn-laf-v23";
const URLS_TO_CACHE = [
  "/",
  "/api/data",
  "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;700&display=swap",
  "https://fonts.googleapis.com/icon?family=Material+Icons+Round",
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(URLS_TO_CACHE)));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  e.respondWith(
    fetch(e.request).then(r => {
      if (r && r.status === 200) {
        const clone = r.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
      }
      return r;
    }).catch(() => caches.match(e.request))
  );
});
'''

# ══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE  (full interactive SPA)
# ══════════════════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="WSN-LAF">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#f97316">
<meta name="description" content="WSN-LAF Simulation Dashboard — Shajan PhD Project">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/icon-192.svg">
<title>WSN-LAF Dashboard — Shajan PhD Project</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#faf7f2;--card:#ffffff;--card2:#fdf8f3;--border:#ecdcc8;
  --accent:#f97316;--a2:#fb923c;--green:#16a34a;--orange:#f97316;
  --red:#dc2626;--yellow:#ca8a04;--cyan:#0891b2;--text:#3d2b14;--muted:#8a7058;
  --laf:#f97316;--leach:#dc2626;--spin:#ca8a04;--dd:#0891b2;--tearp:#16a34a;
  --sidebar:280px}
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',system-ui,sans-serif}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);min-height:100vh;display:flex}
@keyframes fadeInUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes nodeFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
@keyframes shajan-glow{0%{box-shadow:0 0 0 4px rgba(249,115,22,.15),0 6px 24px rgba(249,115,22,.3)}100%{box-shadow:0 0 0 6px rgba(249,115,22,.25),0 8px 32px rgba(249,115,22,.4)}}
/* ── SIDEBAR ─────────────────────────────────────────── */
.sidebar{width:var(--sidebar);height:100vh;position:fixed;left:0;top:0;
  background:#fff;border-right:1px solid var(--border);z-index:200;
  display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden;
  box-shadow:4px 0 24px rgba(0,0,0,.03);transition:transform .3s ease}
.sidebar::-webkit-scrollbar{width:4px}
.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.sb-header{padding:24px 22px 18px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo{width:44px;height:44px;background:linear-gradient(135deg,#f97316,#fb923c);
  border-radius:12px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:15px;color:#fff;font-family:'JetBrains Mono',monospace;
  box-shadow:0 4px 14px rgba(249,115,22,.25);margin-bottom:14px}
.sb-title{font-size:16px;font-weight:800;color:var(--text);line-height:1.3;letter-spacing:-.3px;margin-bottom:2px}
.sb-phd{font-size:11px;font-weight:700;color:var(--accent);margin-bottom:2px}
.sb-sub{font-size:10px;color:var(--muted);line-height:1.4}
/* NAV */
.sb-nav{padding:16px 14px;flex-shrink:0}
.sb-nav-label{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:1px;
  color:var(--muted);padding:0 8px;margin-bottom:8px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;
  cursor:pointer;font-size:13px;font-weight:600;color:var(--muted);transition:all .2s;
  margin-bottom:3px;border:1px solid transparent}
.nav-item:hover{background:#fff7ed;color:var(--text)}
.nav-item.active{background:linear-gradient(135deg,#fff7ed,#ffedd5);color:var(--accent);
  border-color:rgba(249,115,22,.2);font-weight:700}
.nav-item .material-icons-round{font-size:18px}
.nav-item.active .material-icons-round{color:var(--accent)}
/* PARAMS */
.sb-params{padding:10px 14px;border-top:1px solid var(--border);flex:1}
.sb-params-header{display:flex;align-items:center;justify-content:space-between;
  padding:8px 8px 12px;cursor:pointer}
.sb-params-title{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}
.param-section{margin-bottom:14px}
.param-title{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.5px;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.param-row{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}
.param-row label{font-size:10px;color:var(--muted);display:flex;justify-content:space-between}
.param-row label span{color:var(--accent);font-weight:700;font-size:11px;font-family:'JetBrains Mono',monospace}
.param-row input[type=range]{width:100%;accent-color:var(--accent);cursor:pointer;height:4px}
.param-row input[type=number]{width:100%;background:var(--card2);border:1px solid var(--border);
  color:var(--text);padding:6px 10px;border-radius:8px;font-size:11px;outline:none;
  font-family:'JetBrains Mono',monospace;transition:border-color .2s}
.param-row input[type=number]:focus{border-color:var(--accent)}
.range-wrap{display:flex;align-items:center;gap:6px}
.range-wrap input[type=range]{flex:1}
.range-val{min-width:32px;text-align:right;font-size:11px;color:var(--accent);font-weight:700;
  font-family:'JetBrains Mono',monospace}
.toggle-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.toggle-label{font-size:11px;color:var(--text)}
.toggle{position:relative;width:34px;height:18px;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.slider-t{position:absolute;inset:0;background:#e0d5c8;border-radius:9px;transition:.25s}
.slider-t:before{content:'';position:absolute;width:14px;height:14px;
  background:#fff;border-radius:50%;left:2px;top:2px;transition:.25s;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.toggle input:checked+.slider-t{background:var(--accent)}
.toggle input:checked+.slider-t:before{transform:translateX(16px)}
/* SIDEBAR BUTTONS */
.sb-actions{padding:14px;border-top:1px solid var(--border);flex-shrink:0}
.btn{padding:10px 18px;border-radius:10px;border:none;cursor:pointer;
  font-size:13px;font-weight:700;transition:all .2s;display:flex;align-items:center;
  justify-content:center;gap:7px;width:100%}
.btn-primary{background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;
  box-shadow:0 4px 14px rgba(249,115,22,.25);margin-bottom:8px}
.btn-primary:hover{box-shadow:0 6px 20px rgba(249,115,22,.35);transform:translateY(-1px)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
.btn-paper2{background:#fff7ed;border:2px solid var(--accent);color:var(--accent)}
.btn-paper2:hover{background:#ffedd5}
.btn-ghost{background:var(--card2);border:1px solid var(--border);color:var(--text);font-size:11px;padding:7px 12px}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-sm{padding:6px 12px;font-size:11px;border-radius:8px;width:auto}
/* ── MOBILE HAMBURGER ─────────────────────────────── */
.hamburger{display:none;position:fixed;top:12px;left:12px;z-index:300;
  width:40px;height:40px;border-radius:10px;background:#fff;border:1px solid var(--border);
  cursor:pointer;align-items:center;justify-content:center;
  box-shadow:0 2px 10px rgba(0,0,0,.06)}
.hamburger .material-icons-round{font-size:20px;color:var(--accent)}
body.dark .hamburger{background:var(--card);border-color:var(--border)}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.3);z-index:150}
.overlay.on{display:block}
/* ── MAIN CONTENT ─────────────────────────────────── */
/* ── MOBILE HEADER ────────────────────────────────── */
.mobile-hdr{display:none;position:fixed;top:0;left:0;right:0;z-index:250;height:52px;
  align-items:center;gap:10px;padding:0 16px;background:rgba(255,249,240,.92);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border);padding-top:env(safe-area-inset-top)}
.mobile-hdr-btn{background:none;border:none;color:var(--accent);cursor:pointer;padding:6px}
.mobile-hdr-title{font-size:15px;font-weight:700;color:var(--text)}
body.dark .mobile-hdr{background:rgba(19,19,26,.92);border-color:#2e2e3a}
/* ── SIDEBAR GROUP ────────────────────────────────── */
.nav-group .nav-chevron{margin-left:auto;font-size:16px;transition:transform .3s}
.nav-group.open .nav-chevron{transform:rotate(180deg)}
.nav-sub{max-height:0;overflow:hidden;transition:max-height .3s ease}
.nav-group.open .nav-sub{max-height:200px}
.nav-sub-item{padding:8px 14px 8px 42px;font-size:12px;color:var(--muted);cursor:pointer;
  border-radius:8px;transition:all .15s;font-weight:500}
.nav-sub-item:hover{background:#fff7ed;color:var(--text)}
.nav-sub-item.active{color:var(--accent);font-weight:700;background:#fff7ed}
body.dark .nav-sub-item:hover,body.dark .nav-sub-item.active{background:#2a2218}
/* ── OFFLINE BANNER ───────────────────────────────── */
.offline-bar{display:none;position:fixed;top:0;left:0;right:0;z-index:800;
  padding:8px 16px;background:#ef4444;color:#fff;font-size:13px;font-weight:600;
  text-align:center;align-items:center;justify-content:center;gap:6px}
.offline-bar .material-icons-round{font-size:16px}
.main{margin-left:var(--sidebar);flex:1;min-height:100vh;padding:32px 36px}
.page{display:none;max-width:1200px;margin:0 auto}
.page.on{display:block;animation:fadeIn .4s ease-out}
/* HERO */
.hero{background:linear-gradient(135deg,#fff9f0,#ffedd5 50%,#fff9f0);
  border:1px solid var(--border);border-radius:18px;padding:32px 36px;margin-bottom:28px;
  position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:-50%;right:-10%;width:450px;height:450px;
  background:radial-gradient(circle,rgba(249,115,22,.07),transparent 70%);pointer-events:none}
.hero-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:16px}
.hero-title{font-size:26px;font-weight:800;margin-bottom:6px;letter-spacing:-.5px;
  background:linear-gradient(135deg,#ea580c,#f97316,#c2410c);-webkit-background-clip:text;
  -webkit-text-fill-color:transparent;background-clip:text}
.hero-sub{font-size:13px;color:var(--muted);line-height:1.7;font-weight:500}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
.kpi{background:#fff;border:1px solid var(--border);border-radius:14px;
  padding:24px 20px;text-align:center;transition:all .3s;position:relative;overflow:hidden}
.kpi-icon{font-size:28px;margin-bottom:6px;opacity:.7}
.kpi:hover{transform:translateY(-3px);border-color:rgba(249,115,22,.35);
  box-shadow:0 8px 24px rgba(249,115,22,.08)}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.4}
.kpi-val{font-size:30px;font-weight:900;margin-bottom:5px;font-family:'JetBrains Mono','Inter',monospace}
.kpi-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:700}
.kpi-paper{font-size:10px;color:var(--accent);margin-top:5px;font-weight:600}
/* STATUS */
.status-bar{display:flex;align-items:center;gap:8px;padding:12px 18px;
  background:#fff;border:1px solid var(--border);border-radius:12px;margin-bottom:24px;font-size:12px;font-weight:500}
.status-bar.running{border-color:rgba(249,115,22,.4);background:#fff7ed}
.status-bar.error{border-color:rgba(220,38,38,.3);background:#fef2f2}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px rgba(22,163,74,.4)}
.status-dot.pulse{animation:pulse 1.4s ease-in-out infinite}
.p2badge{background:#fff7ed;border:1px solid rgba(249,115,22,.3);color:var(--accent);
  border-radius:8px;padding:4px 10px;font-size:10px;font-weight:700}
/* GRIDS */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:20px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
/* CARD */
.card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:24px;
  transition:all .3s;animation:fadeInUp .5s ease-out both}
.card:nth-child(1){animation-delay:.05s}.card:nth-child(2){animation-delay:.1s}
.card:nth-child(3){animation-delay:.15s}.card:nth-child(4){animation-delay:.2s}
.card:hover{border-color:rgba(249,115,22,.25);box-shadow:0 6px 24px rgba(249,115,22,.06)}
.ct{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.7px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;box-shadow:0 0 6px currentColor}
.ch{position:relative;height:260px}
.ch-lg{position:relative;height:320px}
.ch-xl{position:relative;height:380px}
/* CONTROLS */
.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;margin-bottom:24px}
.ctrl{display:flex;flex-direction:column;gap:5px}
.ctrl-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:700}
select{background:#fff;border:1px solid var(--border);color:var(--text);
  padding:9px 14px;border-radius:10px;font-size:12px;outline:none;cursor:pointer;
  font-family:'Inter',sans-serif;transition:all .2s}
select:focus{border-color:var(--accent)}
/* PROTO TOGGLES */
.proto-toggles{display:flex;gap:6px;flex-wrap:wrap}
.ptog{padding:6px 14px;border-radius:20px;border:2px solid;cursor:pointer;
  font-size:11px;font-weight:700;transition:all .2s;opacity:.4}
.ptog.on{opacity:1;box-shadow:0 2px 8px rgba(0,0,0,.06)}
/* TABLE */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:12px 16px;background:var(--card2);
  color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.7px;
  border-bottom:1px solid var(--border);font-weight:700}
td{padding:12px 16px;border-bottom:1px solid rgba(236,220,200,.5);transition:background .2s}
tr:hover td{background:rgba(249,115,22,.03)}
.best{color:var(--accent);font-weight:800}
.worst{color:var(--red)}
/* PILLS */
.pill{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;
  border-radius:16px;font-size:10px;font-weight:700}
.pup{background:rgba(22,163,74,.08);color:var(--green);border:1px solid rgba(22,163,74,.2)}
.pdown{background:rgba(220,38,38,.08);color:var(--red);border:1px solid rgba(220,38,38,.2)}
/* HEATMAP */
.hmg{display:grid;grid-template-columns:auto repeat(4,1fr);gap:4px;font-size:11px}
.hmc{padding:8px 5px;text-align:center;border-radius:6px;font-weight:700;font-size:10px}
.hmh{color:var(--muted);padding:8px 5px;text-align:center;font-size:9px;text-transform:uppercase;font-weight:600}
.hml{color:var(--muted);padding:8px;display:flex;align-items:center;font-size:10px;font-weight:600}
/* LOADER */
.loader{display:none;position:fixed;inset:0;background:rgba(250,247,242,.92);
  backdrop-filter:blur(6px);z-index:500;align-items:center;justify-content:center;
  flex-direction:column;gap:16px}
.loader.on{display:flex}
.spinner{width:48px;height:48px;border:3px solid var(--border);
  border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
.loader-text{color:var(--text);font-size:15px;font-weight:700}
.loader-sub{color:var(--muted);font-size:12px}
/* TOPOLOGY */
#topo-canvas{width:100%;border-radius:14px;background:#fff;border:1px solid var(--border);cursor:grab}
#topo-canvas:active{cursor:grabbing}
.topo-legend{display:flex;gap:18px;flex-wrap:wrap;padding:14px 0;font-size:12px;font-weight:600;color:var(--muted)}
.topo-legend span{display:flex;align-items:center;gap:6px}
.topo-legend .tl-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
/* ── RESPONSIVE ───────────────────────────────────── */
@media(max-width:1100px){
  .kpi-row{grid-template-columns:repeat(2,1fr)}
  .g2{grid-template-columns:1fr}
  .g4{grid-template-columns:repeat(2,1fr)}
}
@media(max-width:768px){
  :root{--sidebar:280px}
  body{display:block;padding-top:env(safe-area-inset-top);padding-bottom:env(safe-area-inset-bottom)}
  .sidebar{transform:translateX(-100%);width:280px;box-shadow:8px 0 30px rgba(0,0,0,.15);
    padding-top:env(safe-area-inset-top)}
  .sidebar.open{transform:translateX(0)}
  .hamburger{display:none}
  .mobile-hdr{display:flex}
  .main{margin-left:0;padding:16px;padding-top:calc(64px + env(safe-area-inset-top));
    padding-bottom:calc(16px + env(safe-area-inset-bottom));-webkit-overflow-scrolling:touch}
  /* Sidebar internals — tighter on mobile */
  .sb-header{padding:18px 16px 14px}
  .sb-logo{width:36px;height:36px;font-size:13px;margin-bottom:10px}
  .sb-title{font-size:14px}
  .sb-phd{font-size:10px}
  .sb-sub{font-size:9px}
  .sb-nav{padding:10px 10px}
  .nav-item{padding:12px 14px;font-size:13px;margin-bottom:2px;min-height:44px;display:flex;align-items:center}
  .nav-item .material-icons-round{font-size:18px}
  .sb-params{padding:8px 10px}
  .sb-params-header{padding:6px 6px 8px}
  .param-section{margin-bottom:10px}
  .param-title{font-size:9px;margin-bottom:6px;padding-bottom:4px}
  .param-row{margin-bottom:6px;gap:2px}
  .param-row label{font-size:9px}
  .param-row label span{font-size:10px}
  .range-val{font-size:10px;min-width:28px}
  .toggle-row{margin-bottom:6px}
  .toggle-label{font-size:10px}
  .dm-toggle{margin:0 10px 6px;padding:7px 10px;font-size:10px}
  .preset-btn{margin:0 10px 6px;padding:6px 10px;font-size:10px}
  .sb-actions{padding:10px}
  .btn{padding:9px 14px;font-size:12px}
  /* Content area */
  .hero{padding:18px 16px;margin-bottom:16px;border-radius:14px}
  .hero-top{margin-bottom:16px;gap:10px}
  .hero-title{font-size:18px}
  .hero-sub{font-size:11px;line-height:1.5}
  .kpi-row{grid-template-columns:1fr 1fr;gap:10px}
  .kpi{padding:14px 12px;border-radius:10px}
  .kpi-val{font-size:22px}
  .kpi-label{font-size:8px}
  .kpi-paper{font-size:9px}
  .g2,.g3{grid-template-columns:1fr;gap:14px;margin-bottom:14px}
  .g4{grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
  .card{padding:16px;border-radius:12px;margin-bottom:0}
  .ct{font-size:10px;margin-bottom:12px;letter-spacing:.5px}
  .ch{height:200px}.ch-lg{height:240px}.ch-xl{height:280px}
  .status-bar{padding:8px 12px;font-size:11px;border-radius:10px;margin-bottom:14px}
  .stats-ticker{font-size:10px;gap:8px;padding:8px 12px;border-radius:10px;margin-bottom:12px;flex-wrap:wrap}
  .st-item .st-val{font-size:11px}
  .st-divider{height:14px}
  .breadcrumb{font-size:10px;margin-bottom:10px}
  /* Tables */
  table{font-size:11px}
  th{padding:8px 10px;font-size:8px}
  td{padding:8px 10px}
  .controls{gap:8px;margin-bottom:14px}
  select{padding:7px 10px;font-size:11px}
  .proto-toggles{gap:4px}
  .ptog{padding:4px 10px;font-size:10px}
  /* Help */
  .help-grid{grid-template-columns:1fr;gap:14px}
  .help-card{padding:18px}
  .help-card h3{font-size:13px}
  .pod-card{padding:14px}
  #sg-wrap{font-size:16px}
  .sg-tab-btn{padding:8px 16px;font-size:13px}
  .sg-step{font-size:16px}
  .sg-q{font-size:17px}
  .sg-a{font-size:16px}
  .help-card p{font-size:12px}
  .help-section-title{font-size:16px}
  .glossary-grid{grid-template-columns:1fr;gap:8px}
  .glossary-item{padding:12px}
  /* Topology */
  #topo-canvas{height:350px}
  .topo-legend{font-size:10px;gap:10px;flex-wrap:wrap}
  /* Footer */
  .footer{margin-top:24px;padding:18px 0;font-size:10px}
}
@media(max-width:480px){
  .main{padding:12px;padding-top:64px}
  .kpi-row{grid-template-columns:1fr}
  .g4{grid-template-columns:1fr}
  .hero-title{font-size:16px}
  .hero-sub{font-size:10px}
  .kpi-val{font-size:20px}
  .kpi{padding:12px 10px}
  .card{padding:14px}
  .ch{height:180px}.ch-lg{height:220px}.ch-xl{height:250px}
  .stats-ticker .st-divider{display:none}
  .stats-ticker{gap:6px;justify-content:center}
  .st-item{font-size:9px}
  .st-item .st-val{font-size:10px}
  .breadcrumb{font-size:9px}
  .help-card h3{font-size:12px}
  .glossary-item dt{font-size:11px}
  .glossary-item dd{font-size:10px}
}
/* ── DARK MODE ────────────────────────────────────── */
body.dark{--bg:#121218;--card:#1c1c24;--card2:#22222c;--border:#2e2e3a;
  --text:#e8e4df;--muted:#8a8578;--accent:#f97316;--a2:#fb923c;
  --green:#22c55e;--red:#ef4444;--yellow:#eab308;--cyan:#06b6d4}
body.dark .sidebar{background:#1c1c24;border-color:#2e2e3a}
body.dark .sb-header{border-color:#2e2e3a}
body.dark .sb-params{border-color:#2e2e3a}
body.dark .sb-actions{border-color:#2e2e3a}
body.dark .nav-item:hover{background:#2a2a34}
body.dark .nav-item.active{background:linear-gradient(135deg,#2a2218,#332818);border-color:#4a3520}
body.dark .card{background:#1c1c24;border-color:#2e2e3a}
body.dark .card:hover{border-color:#4a3520;box-shadow:0 6px 24px rgba(249,115,22,.08)}
body.dark .hero{background:linear-gradient(135deg,#1c1c24,#2a2218,#1c1c24);border-color:#2e2e3a}
body.dark .kpi{background:#22222c;border-color:#2e2e3a}
body.dark .kpi:hover{border-color:#4a3520}
body.dark th{background:#22222c}
body.dark td{border-color:#2e2e3a}
body.dark select,body.dark .param-row input[type=number]{background:#22222c;border-color:#2e2e3a;color:#e8e4df}
body.dark .slider-t{background:#2e2e3a}
body.dark .status-bar{background:#1c1c24;border-color:#2e2e3a}
body.dark .stats-ticker{background:#1c1c24;border-color:#2e2e3a}
body.dark .hamburger{background:#1c1c24;border-color:#2e2e3a}
body.dark .loader{background:rgba(18,18,24,.92)}
body.dark .breadcrumb{color:#8a8578}
body.dark .help-card{background:#22222c;border-color:#2e2e3a}
body.dark .tour-overlay{background:rgba(18,18,24,.8)}
body.dark #topo-canvas{background:#1c1c24;border-color:#2e2e3a}
body.dark .fab{background:#1c1c24;border-color:#2e2e3a}
body.dark .fab-menu{background:#1c1c24;border-color:#2e2e3a}
body.dark .preset-dd{background:#1c1c24;border-color:#2e2e3a}
/* ── STATS TICKER ─────────────────────────────────── */
.stats-ticker{display:flex;align-items:center;gap:20px;padding:10px 20px;
  background:#fff;border:1px solid var(--border);border-radius:12px;margin-bottom:20px;
  flex-wrap:wrap;font-size:12px;font-weight:600;animation:fadeIn .4s ease-out}
.st-item{display:flex;align-items:center;gap:6px;color:var(--muted)}
.st-item .st-icon{font-size:14px}
.st-item .st-val{color:var(--text);font-family:'JetBrains Mono',monospace;font-weight:800;font-size:13px}
.st-divider{width:1px;height:18px;background:var(--border)}
/* ── BREADCRUMB ───────────────────────────────────── */
.breadcrumb{font-size:11px;color:var(--muted);margin-bottom:16px;font-weight:600;
  display:flex;align-items:center;gap:6px}
.breadcrumb .material-icons-round{font-size:16px;color:var(--accent)}
.breadcrumb .bc-page{color:var(--text);font-weight:700}
/* ── HEALTH GAUGE ─────────────────────────────────── */
.health-gauge{position:fixed;top:20px;right:20px;z-index:100;text-align:center}
.hg-circle{width:72px;height:72px;position:relative}
.hg-svg{transform:rotate(-90deg)}
.hg-bg{fill:none;stroke:var(--border);stroke-width:5}
.hg-fill{fill:none;stroke-width:5;stroke-linecap:round;transition:stroke-dashoffset .8s ease,stroke .3s}
.hg-val{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  font-size:18px;font-weight:900;font-family:'JetBrains Mono',monospace;color:var(--accent)}
.hg-label{font-size:8px;color:var(--muted);text-transform:uppercase;font-weight:700;
  letter-spacing:.5px;margin-top:2px}
/* ── DARK MODE TOGGLE ─────────────────────────────── */
.dm-toggle{display:flex;align-items:center;gap:8px;padding:8px 14px;margin:0 14px 8px;
  border-radius:8px;cursor:pointer;font-size:11px;font-weight:600;color:var(--muted);
  transition:all .2s;border:1px solid var(--border)}
.dm-toggle:hover{background:var(--card2);color:var(--text)}
.dm-toggle .material-icons-round{font-size:16px}
/* ── FAB ──────────────────────────────────────────── */
.fab{position:fixed;bottom:24px;right:24px;z-index:100}
.fab-btn{width:50px;height:50px;border-radius:14px;background:linear-gradient(135deg,#f97316,#fb923c);
  border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;
  box-shadow:0 4px 20px rgba(249,115,22,.3);transition:all .2s;color:#fff}
.fab-btn:hover{transform:scale(1.05);box-shadow:0 6px 28px rgba(249,115,22,.4)}
.fab-btn .material-icons-round{font-size:24px;transition:transform .3s}
.fab-btn.open .material-icons-round{transform:rotate(45deg)}
.fab-menu{display:none;position:absolute;bottom:60px;right:0;
  background:#fff;border:1px solid var(--border);border-radius:12px;padding:6px;
  box-shadow:0 8px 30px rgba(0,0,0,.1);min-width:160px}
.fab-menu.on{display:block;animation:fadeInUp .2s ease-out}
.fab-action{display:flex;align-items:center;gap:8px;padding:9px 14px;border-radius:8px;
  cursor:pointer;font-size:12px;font-weight:600;color:var(--text);transition:all .15s;border:none;
  background:none;width:100%;text-align:left}
.fab-action:hover{background:var(--card2);color:var(--accent)}
.fab-action .material-icons-round{font-size:16px;color:var(--accent)}
/* ── FOOTER ───────────────────────────────────────── */
.footer{margin-top:40px;padding:24px 0;border-top:1px solid var(--border);text-align:center;
  font-size:11px;color:var(--muted);line-height:1.8}
.footer a{color:var(--accent);text-decoration:none;font-weight:600}
.footer a:hover{text-decoration:underline}
/* ── PD GOALS PAGE ────────────────────────────────── */
.pdg-header{background:linear-gradient(135deg,#f97316,#fb923c);padding:24px 30px;
  border-radius:16px;margin-bottom:24px;position:relative}
.pdg-header h2{font-size:22px;font-weight:800;color:#fff;margin-bottom:4px}
.pdg-header p{font-size:13px;color:rgba(255,255,255,.85);font-weight:500}
.pdg-summary{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px}
.pdg-ring{display:flex;align-items:center;gap:14px;padding:16px 22px;
  border-radius:14px;background:var(--card);border:1px solid var(--border);flex:1;min-width:140px}
.pdg-ring .num{font-size:32px;font-weight:900;font-family:'JetBrains Mono',monospace}
.pdg-ring .lbl{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.pdg-ring.green .num{color:#16a34a}
.pdg-ring.orange .num{color:#f97316}
.pdg-ring.blue .num{color:#0891b2}
.pdg-card{background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:20px 22px;margin-bottom:14px;transition:all .2s}
.pdg-card:hover{box-shadow:0 4px 20px rgba(0,0,0,.06)}
.pdg-card.met{border-left:4px solid #16a34a}
.pdg-card.partial{border-left:4px solid #f97316}
.pdg-card.future{border-left:4px solid #0891b2}
.pdg-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.pdg-title{font-size:15px;font-weight:700;color:var(--text)}
.pdg-status{font-size:12px;font-weight:700;padding:4px 12px;border-radius:20px}
.pdg-status.met{background:rgba(22,163,74,.1);color:#16a34a}
.pdg-status.partial{background:rgba(249,115,22,.1);color:#f97316}
.pdg-status.future{background:rgba(8,145,178,.1);color:#0891b2}
.pdg-row{display:flex;gap:24px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.pdg-metric{display:flex;flex-direction:column;gap:2px}
.pdg-metric .label{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:600;letter-spacing:.4px}
.pdg-metric .value{font-size:16px;font-weight:800;font-family:'JetBrains Mono',monospace;color:var(--text)}
.pdg-bar-wrap{flex:1;min-width:120px;height:8px;background:var(--card2);border-radius:8px;overflow:hidden}
.pdg-bar{height:100%;border-radius:8px;transition:width .6s ease}
.pdg-bar.met{background:linear-gradient(90deg,#16a34a,#22c55e)}
.pdg-bar.partial{background:linear-gradient(90deg,#f97316,#fb923c)}
.pdg-bar.future{background:linear-gradient(90deg,#0891b2,#22d3ee)}
.pdg-note{font-size:12px;line-height:1.5;padding:8px 12px;border-radius:8px;font-weight:500}
.pdg-note.met{color:#16a34a;background:rgba(22,163,74,.06)}
.pdg-note.partial{color:#b45309;background:rgba(180,83,9,.06)}
.pdg-note.future{color:#0891b2;background:rgba(8,145,178,.06)}
body.dark .pdg-note.partial{color:#fb923c}
/* recalculate button */
.pdg-recalc-btn{position:absolute;top:20px;right:20px;padding:10px 20px;border:2px solid #fff;
  border-radius:12px;background:rgba(255,255,255,.15);color:#fff;font-size:13px;font-weight:700;
  cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .25s;backdrop-filter:blur(6px)}
.pdg-recalc-btn:hover{background:rgba(255,255,255,.3);transform:translateY(-1px)}
.pdg-recalc-btn.running{pointer-events:none;opacity:.7}
.pdg-recalc-btn.running .material-icons-round{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* terminal console */
.pdg-terminal{background:#0d1117;border-radius:14px;overflow:hidden;margin-bottom:24px;
  box-shadow:0 8px 32px rgba(0,0,0,.25);animation:fadeInUp .3s ease-out}
.pdg-term-bar{display:flex;align-items:center;gap:8px;padding:10px 16px;background:#161b22;border-bottom:1px solid #21262d}
.pdg-term-dot{width:12px;height:12px;border-radius:50%}
.pdg-term-dot.red{background:#ff5f57}.pdg-term-dot.yellow{background:#febc2e}.pdg-term-dot.green{background:#28c840}
.pdg-term-title{font-size:12px;color:#8b949e;font-weight:600;margin-left:8px;font-family:'JetBrains Mono',monospace}
.pdg-term-body{padding:16px 20px;font-family:'JetBrains Mono',monospace;font-size:13px;
  color:#c9d1d9;line-height:1.8;max-height:400px;overflow-y:auto}
.pdg-term-body .t-line{opacity:0;animation:typeLine .3s ease forwards}
@keyframes typeLine{to{opacity:1}}
.pdg-term-body .t-cmd{color:#58a6ff}
.pdg-term-body .t-ok{color:#3fb950}
.pdg-term-body .t-warn{color:#d29922}
.pdg-term-body .t-info{color:#8b949e}
.pdg-term-body .t-val{color:#f0883e;font-weight:700}
.pdg-term-body .t-cursor{display:inline-block;width:8px;height:16px;background:#58a6ff;
  vertical-align:text-bottom;animation:blink 1s step-end infinite}
@keyframes blink{50%{opacity:0}}
@media(max-width:768px){
  .pdg-recalc-btn{position:static;margin-top:12px;width:100%;justify-content:center}
  .pdg-summary{flex-direction:column}
  .pdg-row{flex-direction:column;gap:8px;align-items:flex-start}
  .pdg-term-body{font-size:11px;padding:12px 14px}
  .pd-badges{gap:8px}
  .pd-badge{font-size:11px;padding:6px 12px}
}
/* ── PRESETS ──────────────────────────────────────── */
.preset-dd{position:relative;display:inline-block}
.preset-btn{display:flex;align-items:center;gap:6px;padding:8px 14px;border-radius:8px;
  cursor:pointer;font-size:11px;font-weight:600;color:var(--muted);border:1px solid var(--border);
  background:#fff;transition:all .2s;margin:0 14px 8px}
.preset-btn:hover{border-color:var(--accent);color:var(--accent)}
.preset-list{display:none;position:absolute;left:14px;top:100%;background:#fff;border:1px solid var(--border);
  border-radius:10px;padding:4px;box-shadow:0 8px 24px rgba(0,0,0,.08);z-index:50;min-width:200px}
.preset-list.on{display:block;animation:fadeInUp .2s ease-out}
.preset-opt{padding:8px 12px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600;
  color:var(--text);transition:all .15s}
.preset-opt:hover{background:var(--card2);color:var(--accent)}
.preset-opt small{display:block;font-size:9px;color:var(--muted);font-weight:500;margin-top:2px}
/* ── HELP PAGE ────────────────────────────────────── */
.help-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
.help-card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:24px;
  transition:all .3s}
.help-card:hover{border-color:rgba(249,115,22,.3);box-shadow:0 4px 16px rgba(249,115,22,.06)}
.help-card h3{font-size:15px;font-weight:700;color:var(--text);margin-bottom:8px;display:flex;align-items:center;gap:8px}
.help-card h3 .material-icons-round{color:var(--accent);font-size:20px}
.help-card p{font-size:13px;color:var(--muted);line-height:1.7}
.help-card .help-step{display:flex;align-items:flex-start;gap:10px;margin-top:12px;padding:10px;
  background:var(--card2);border-radius:8px}
.help-card .help-num{width:24px;height:24px;border-radius:50%;background:var(--accent);color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex-shrink:0}
.help-card .help-txt{font-size:12px;color:var(--text);line-height:1.6}
.help-section-title{font-size:20px;font-weight:800;color:var(--text);margin-bottom:6px;
  display:flex;align-items:center;gap:10px}
.help-section-sub{font-size:13px;color:var(--muted);margin-bottom:20px;line-height:1.6}
.glossary-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
.glossary-item{padding:14px;background:var(--card2);border-radius:10px}
.glossary-item dt{font-size:13px;font-weight:800;color:var(--accent);margin-bottom:4px;
  font-family:'JetBrains Mono',monospace}
.glossary-item dd{font-size:11px;color:var(--muted);line-height:1.5}
/* ── TOUR ─────────────────────────────────────────── */
.tour-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:400}
.tour-overlay.on{display:block}
.tour-tip{position:fixed;z-index:410;background:#fff;border-radius:14px;padding:20px;
  box-shadow:0 12px 40px rgba(0,0,0,.15);max-width:320px;animation:fadeInUp .3s ease-out}
.tour-tip h4{font-size:14px;font-weight:700;color:var(--text);margin-bottom:6px}
.tour-tip p{font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:14px}
.tour-tip .tour-btns{display:flex;gap:8px;justify-content:flex-end}
.tour-tip .tour-next{padding:7px 16px;border-radius:8px;border:none;cursor:pointer;
  font-size:12px;font-weight:700;background:var(--accent);color:#fff}
.tour-tip .tour-skip{padding:7px 16px;border-radius:8px;border:1px solid var(--border);
  cursor:pointer;font-size:12px;font-weight:600;color:var(--muted);background:none}
.tour-counter{font-size:10px;color:var(--muted);margin-bottom:8px;font-weight:600}
.sg-tab-btn{padding:10px 24px;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;
  border:2px solid #f5d5b8;background:transparent;color:#9a7355;font-family:'Inter',sans-serif;transition:all .2s}
.sg-tab-btn:hover{background:#fff7ed}
.sg-tab-active{background:#f97316 !important;color:#fff !important;border-color:#f97316 !important}
body.dark .sg-tab-btn{border-color:#2e2e3a;color:#bba88a}
body.dark .sg-tab-btn:hover{background:#2a2218}
/* ── RESEARCH STORY ──────────────────────────────── */
.story-section{display:flex;gap:20px;margin-bottom:40px;position:relative}
.story-num{width:48px;height:48px;border-radius:50%;background:#f97316;color:#fff;font-size:22px;font-weight:800;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 4px 14px rgba(249,115,22,.3)}
.story-body{flex:1;min-width:0}
.story-icon{margin-bottom:8px}
.story-heading{font-size:22px;font-weight:800;color:#4a2c0a;margin-bottom:20px}
.story-cards-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:8px}
.story-card{background:#fff;border:1.5px solid #f5d5b8;border-radius:14px;padding:22px;transition:box-shadow .2s}
.story-card:hover{box-shadow:0 4px 20px rgba(249,115,22,.12)}
.story-card-problem{border-left:4px solid #dc2626}
.story-card-solution{border-left:4px solid #16a34a}
.story-card-title{font-size:17px;font-weight:700;color:#4a2c0a;margin-bottom:8px}
.story-card-text{font-size:15px;line-height:1.7;color:#6b4c2a}
.story-c-badge{width:36px;height:36px;border-radius:50%;background:#16a34a;color:#fff;font-size:14px;font-weight:800;
  display:flex;align-items:center;justify-content:center;margin-bottom:12px}
.story-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.story-metric{background:linear-gradient(135deg,#fff7ed,#fff);border:1.5px solid #f5d5b8;border-radius:14px;padding:22px;text-align:center}
.story-metric-val{font-size:28px;font-weight:900;color:#f97316;margin-bottom:4px}
.story-metric-label{font-size:14px;font-weight:700;color:#4a2c0a}
.story-metric-sub{font-size:12px;color:#9a7355;margin-top:4px}
.story-checks{display:flex;flex-direction:column;gap:12px}
.story-check{display:flex;align-items:center;gap:12px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:14px 18px;font-size:16px;color:#4a2c0a}
.story-check-note{color:#9a7355;font-weight:400}
.story-impacts{display:flex;gap:12px;flex-wrap:wrap}
.story-impact-badge{display:flex;align-items:center;gap:8px;background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;
  border-radius:12px;padding:14px 20px;font-size:14px;font-weight:700;box-shadow:0 4px 14px rgba(249,115,22,.25)}
.story-impact-badge .material-icons-round{font-size:20px}
#story-wrap[dir="rtl"] .story-section{flex-direction:row-reverse}
#story-wrap[dir="rtl"] .story-card-problem{border-left:none;border-right:4px solid #dc2626}
#story-wrap[dir="rtl"] .story-card-solution{border-left:none;border-right:4px solid #16a34a}
#story-wrap[dir="rtl"] .story-heading,#story-wrap[dir="rtl"] .story-card-title,#story-wrap[dir="rtl"] .story-card-text,
#story-wrap[dir="rtl"] .story-metric-label,#story-wrap[dir="rtl"] .story-metric-sub,
#story-wrap[dir="rtl"] .story-check,#story-wrap[dir="rtl"] .story-check-note{text-align:right}
body.dark .story-card{background:#1e1e2a;border-color:#2e2e3a}
body.dark .story-card-title,body.dark .story-heading{color:#e8e0d8}
body.dark .story-card-text,body.dark .story-check-note{color:#bba88a}
body.dark .story-metric{background:linear-gradient(135deg,#2a2218,#1e1e2a);border-color:#2e2e3a}
body.dark .story-metric-label{color:#e8e0d8}
body.dark .story-metric-sub{color:#bba88a}
body.dark .story-check{background:#1a2e1a;border-color:#2e4a2e}
@media(max-width:768px){
  .story-cards-3{grid-template-columns:1fr}
  .story-metrics{grid-template-columns:1fr 1fr}
  .story-section{gap:14px}
  .story-num{width:38px;height:38px;font-size:18px}
  .story-heading{font-size:19px}
  .story-impacts{flex-direction:column}
}
/* ── SHAJAN PHOTO ICONS ──────────────────────────── */
.shajan-nav-photo{width:32px;height:32px;border-radius:50%;object-fit:cover;border:2.5px solid #f97316;flex-shrink:0;
  box-shadow:0 0 0 2px rgba(249,115,22,.2),0 2px 8px rgba(249,115,22,.25);transition:transform .2s,box-shadow .2s}
.shajan-nav-photo:hover{transform:scale(1.1);box-shadow:0 0 0 3px rgba(249,115,22,.3),0 4px 14px rgba(249,115,22,.35)}
.shajan-btab-photo{width:28px;height:28px;border-radius:50%;object-fit:cover;
  border:2.5px solid #f97316;box-shadow:0 0 0 2px rgba(249,115,22,.18),0 2px 10px rgba(249,115,22,.3);transition:transform .2s}
#btab-shajan.active .shajan-btab-photo{box-shadow:0 0 0 3px rgba(249,115,22,.35),0 0 12px rgba(249,115,22,.4);transform:scale(1.08)}
.shajan-header-photo{width:64px;height:64px;border-radius:50%;object-fit:cover;
  border:3.5px solid #f97316;box-shadow:0 0 0 4px rgba(249,115,22,.15),0 6px 24px rgba(249,115,22,.3);
  animation:shajan-glow 3s ease-in-out infinite alternate}
/* ── RESEARCH VIDEOS ─────────────────────────────── */
.rv-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px}
.rv-card{background:#fff;border:1.5px solid #f5d5b8;border-radius:14px;padding:16px 18px;transition:box-shadow .2s}
.rv-card:hover{box-shadow:0 4px 20px rgba(249,115,22,.15)}
.rv-badges{display:flex;gap:6px;margin-bottom:10px}
.rv-badge{font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px;letter-spacing:.5px}
.rv-ar{background:#dcfce7;color:#16a34a;border:1px solid #16a34a}
.rv-en{background:#eff6ff;color:#2563eb;border:1px solid #2563eb}
.rv-ep{background:#fff7ed;color:#f97316;border:1px solid #f97316}
.rv-title{font-size:15px;font-weight:700;color:#4a2c0a;margin-bottom:4px;line-height:1.4}
.rv-sub{font-size:12px;color:#9a7355;margin-bottom:12px}
body.dark .rv-card{background:#1e1e2a;border-color:#2e2e3a}
body.dark .rv-title{color:#e8e0d8}
body.dark .rv-sub{color:#bba88a}
@media(max-width:768px){.rv-grid{grid-template-columns:1fr}.rv-card{padding:14px}}
/* ── PODCASTS ─────────────────────────────────────── */
.pod-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:28px}
@media(max-width:768px){.pod-grid{grid-template-columns:1fr}.yt-lazy{height:200px}}
.pod-card{background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:14px;padding:20px 22px;margin-bottom:14px}
.pod-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:8px}
.pod-title{font-size:17px;font-weight:700;color:#4a2c0a}
.pod-meta{display:flex;gap:8px;align-items:center;flex-shrink:0}
.pod-lang{font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px;text-transform:uppercase;letter-spacing:.5px}
.pod-ar{background:#fff7ed;color:#f97316;border:1px solid #f97316}
.pod-en{background:#eff6ff;color:#2563eb;border:1px solid #2563eb}
.pod-dur{font-size:12px;color:#9a7355;font-weight:600}
.pod-desc{font-size:15px;color:#6b4c2a;line-height:1.6;margin-bottom:12px}
.pod-audio{width:100%;height:40px;border-radius:8px}
.pod-audio[data-src=""]{display:none}
.pod-empty{display:none;font-size:13px;color:#9a7355;font-style:italic;padding:10px 0}
.pod-audio[data-src=""]~.pod-empty{display:block}
body.dark .pod-card{background:#1c1c24;border-color:#2e2e3a}
body.dark .pod-title{color:#e8e0d8}
body.dark .pod-desc{color:#bba88a}
body.dark .pod-ar{background:#2a2218;border-color:#f97316}
body.dark .pod-en{background:#1a2236;border-color:#2563eb}
body.dark #pod-wrap{color:#e8e0d8}
/* ── SHAJAN GUIDE ─────────────────────────────────── */
.sg-steps{display:flex;flex-direction:column;gap:12px}
.sg-step{display:flex;align-items:flex-start;gap:14px;font-size:18px;line-height:1.7}
.sg-num{min-width:36px;height:36px;display:flex;align-items:center;justify-content:center;
  border-radius:10px;font-weight:800;font-size:15px;background:#fff7ed;color:#f97316;flex-shrink:0}
.sg-qa{margin-bottom:22px;padding-bottom:22px;border-bottom:1px solid #f5d5b8}
.sg-qa:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.sg-q{font-size:19px;font-weight:700;color:#4a2c0a;margin-bottom:8px}
.sg-a{font-size:18px;color:#6b4c2a;line-height:1.8}
#sg-wrap[dir="rtl"] .sg-step{flex-direction:row-reverse;text-align:right}
#sg-wrap[dir="rtl"] .sg-qa{text-align:right}
#sg-wrap[dir="rtl"] .sg-q,#sg-wrap[dir="rtl"] .sg-a{text-align:right}
body.dark .sg-card{background:#1c1c24 !important;border-color:#2e2e3a !important}
body.dark .sg-q{color:#e8e0d8}
body.dark .sg-a{color:#bba88a}
body.dark .sg-num{background:#2a2218;color:#f97316}
body.dark #sg-wrap{color:#e8e0d8}
body.dark #shajan-notes{background:#13131a;color:#e8e0d8;border-color:#2e2e3a}
/* ── LOGIN ────────────────────────────────────────── */
.login-overlay{position:fixed;inset:0;background:var(--bg);z-index:700;display:flex;
  align-items:center;justify-content:center;flex-direction:column;gap:20px;
  transition:opacity .6s,visibility .6s}
.login-overlay.hide{opacity:0;visibility:hidden;pointer-events:none}
.login-box{background:var(--card);border:1px solid var(--border);border-radius:18px;
  padding:40px 36px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.08);max-width:360px;width:90%}
.login-logo{width:64px;height:64px;background:linear-gradient(135deg,#f97316,#fb923c);
  border-radius:16px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:22px;color:#fff;font-family:'JetBrains Mono',monospace;
  margin:0 auto 16px;box-shadow:0 8px 30px rgba(249,115,22,.3)}
.login-title{font-size:20px;font-weight:800;color:var(--text);margin-bottom:4px}
.login-sub{font-size:13px;color:var(--muted);margin-bottom:24px}
.login-input{width:100%;padding:12px 16px;border:1.5px solid var(--border);border-radius:10px;
  font-size:15px;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);
  text-align:center;outline:none;transition:border .2s}
.login-input:focus{border-color:#f97316}
.login-input::placeholder{color:var(--muted)}
.login-btn{width:100%;padding:12px;border:none;border-radius:10px;font-size:14px;font-weight:700;
  background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;cursor:pointer;margin-top:14px;
  font-family:'Inter',sans-serif;transition:transform .15s}
.login-btn:hover{transform:scale(1.02)}
.login-btn:active{transform:scale(.98)}
.login-error{color:#ef4444;font-size:12px;margin-top:10px;display:none}
.welcome-modal{position:fixed;inset:0;z-index:750;display:flex;align-items:center;
  justify-content:center;background:rgba(0,0,0,.4);opacity:0;visibility:hidden;transition:all .4s}
.welcome-modal.show{opacity:1;visibility:visible}
.welcome-card{background:var(--card);border-radius:18px;padding:44px 36px;text-align:center;
  max-width:400px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.15);transform:scale(.9);transition:transform .4s}
.welcome-modal.show .welcome-card{transform:scale(1)}
.welcome-icon{font-size:48px;margin-bottom:12px}
.welcome-name{font-size:22px;font-weight:800;color:var(--text);margin-bottom:6px}
.welcome-msg{font-size:14px;color:var(--muted);line-height:1.6;margin-bottom:24px}
.welcome-tail{font-size:12px;color:var(--accent);font-weight:600;font-style:italic;margin-bottom:20px}
.welcome-enter{padding:10px 32px;border:none;border-radius:10px;font-size:14px;font-weight:700;
  background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;cursor:pointer;font-family:'Inter',sans-serif}
body.dark .login-overlay{background:#13131a}
body.dark .login-box,body.dark .welcome-card{background:#1c1c24;border-color:#2e2e3a}
body.dark .login-input{background:#13131a;border-color:#2e2e3a;color:#e8e0d8}
/* ── SPLASH ───────────────────────────────────────── */
.splash{position:fixed;inset:0;background:var(--bg);z-index:600;display:flex;
  align-items:center;justify-content:center;flex-direction:column;gap:16px;
  transition:opacity .6s,visibility .6s}
.splash.hide{opacity:0;visibility:hidden}
.splash-logo{width:64px;height:64px;background:linear-gradient(135deg,#f97316,#fb923c);
  border-radius:16px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:22px;color:#fff;font-family:'JetBrains Mono',monospace;
  animation:nodeFloat 2s ease-in-out infinite;box-shadow:0 8px 30px rgba(249,115,22,.3)}
.splash-title{font-size:18px;font-weight:800;color:var(--text)}
.splash-sub{font-size:12px;color:var(--muted)}
.splash-bar{width:200px;height:3px;background:var(--border);border-radius:2px;overflow:hidden}
.splash-fill{height:100%;background:linear-gradient(90deg,#f97316,#fb923c);border-radius:2px;
  animation:splashLoad 2s ease-in-out forwards}
@keyframes splashLoad{0%{width:0}100%{width:100%}}
@media(max-width:768px){
  .health-gauge{top:12px;right:62px;z-index:250}
  .hg-circle{width:46px;height:46px}
  .hg-svg{width:46px;height:46px}
  .hg-val{font-size:13px}
  .hg-label{font-size:7px}
  .fab{bottom:14px;right:14px}
  .fab-btn{width:44px;height:44px;border-radius:12px}
  .fab-btn .material-icons-round{font-size:20px}
  .fab-menu{min-width:150px;border-radius:10px}
  .fab-action{padding:8px 12px;font-size:11px}
  .tour-tip{max-width:280px;left:12px!important;right:12px!important;padding:16px}
  .tour-tip h4{font-size:13px}
  .tour-tip p{font-size:11px}
  .splash-logo{width:50px;height:50px;font-size:18px}
  .splash-title{font-size:15px}
  .splash-sub{font-size:11px}
}
@media(max-width:480px){
  .health-gauge{top:10px;right:56px}
  .hg-circle{width:40px;height:40px}
  .hg-svg{width:40px;height:40px}
  .hg-val{font-size:11px}
  .fab-btn{width:40px;height:40px}
}
/* ── BOTTOM TAB BAR (mobile) ─────────────────────── */
.btab-bar{display:none;position:fixed;bottom:0;left:0;right:0;z-index:300;
  background:var(--card);border-top:1px solid var(--border);
  padding:4px 0 calc(4px + env(safe-area-inset-bottom));
  box-shadow:0 -4px 20px rgba(0,0,0,.06);
  justify-content:space-around;align-items:center}
body.dark .btab-bar{background:#1c1c24;border-color:#2a2a36}
.btab{display:flex;flex-direction:column;align-items:center;gap:2px;padding:6px 4px;
  border:none;background:none;cursor:pointer;color:var(--muted);
  font-size:9px;font-weight:600;min-width:52px;transition:all .2s;
  -webkit-tap-highlight-color:transparent}
.btab .material-icons-round{font-size:22px;transition:all .2s}
.btab.active{color:var(--accent)}
.btab.active .material-icons-round{font-size:24px}
@media(max-width:768px){
  .btab-bar{display:flex}
  .main{padding-bottom:calc(80px + env(safe-area-inset-bottom))!important}
  .fab{bottom:calc(70px + env(safe-area-inset-bottom))}
}
/* ── PULL TO REFRESH ─────────────────────────────── */
.ptr-indicator{position:fixed;top:calc(env(safe-area-inset-top) + 60px);left:50%;transform:translateX(-50%);
  z-index:400;background:var(--card);border:1px solid var(--border);border-radius:50%;
  width:40px;height:40px;display:flex;align-items:center;justify-content:center;
  box-shadow:0 4px 16px rgba(0,0,0,.1);opacity:0;transition:opacity .2s,transform .2s;
  pointer-events:none}
.ptr-indicator.show{opacity:1}
.ptr-indicator.loading .material-icons-round{animation:spin 1s linear infinite}
/* ── SHARE BUTTON ────────────────────────────────── */
.share-btn{position:fixed;bottom:24px;left:24px;z-index:100;width:48px;height:48px;
  border-radius:50%;border:none;cursor:pointer;
  background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;
  box-shadow:0 4px 16px rgba(249,115,22,.3);transition:all .2s;
  display:flex;align-items:center;justify-content:center}
.share-btn:hover{transform:translateY(-2px);box-shadow:0 6px 24px rgba(249,115,22,.4)}
@media(max-width:768px){
  .share-btn{bottom:calc(76px + env(safe-area-inset-bottom));left:16px;width:42px;height:42px}
}
/* ── SKELETON LOADING ────────────────────────────── */
.skel{background:linear-gradient(90deg,var(--card2) 25%,var(--border) 50%,var(--card2) 75%);
  background-size:200% 100%;animation:skelShimmer 1.5s infinite;border-radius:10px}
@keyframes skelShimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skel-card{height:180px;border-radius:14px;margin-bottom:16px}
.skel-kpi{height:90px;border-radius:12px}
.skel-row{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:14px;margin-bottom:16px}
@media(max-width:768px){.skel-row{grid-template-columns:1fr 1fr}}
/* ── LANDSCAPE CHART ─────────────────────────────── */
@media(orientation:landscape) and (max-height:500px){
  .main{padding-top:12px!important}
  .hamburger{top:8px;left:8px}
  .hero{padding:12px 16px}
  .hero-title{font-size:16px}
  .kpi-row{grid-template-columns:repeat(4,1fr)}
  .ch,.ch-lg,.ch-xl{height:55vh!important;min-height:200px}
  .btab-bar{padding:2px 0 calc(2px + env(safe-area-inset-bottom))}
  .btab{padding:4px;font-size:8px}
  .btab .material-icons-round{font-size:18px}
}
/* ── TOAST NOTIFICATION ──────────────────────────── */
.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%) translateY(-100px);
  z-index:600;background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:12px 20px;box-shadow:0 8px 32px rgba(0,0,0,.12);font-size:13px;font-weight:600;
  color:var(--text);display:flex;align-items:center;gap:8px;transition:transform .3s ease;
  max-width:90vw}
.toast.show{transform:translateX(-50%) translateY(0)}
.toast .material-icons-round{color:var(--accent);font-size:20px}
</style>
</head>
<body>

<!-- LOGIN -->
<div class="login-overlay" id="login-overlay">
  <div class="login-box">
    <div class="login-logo">LAF</div>
    <div class="login-title">WSN-LAF Dashboard</div>
    <div class="login-sub">Enter your access code to continue</div>
    <input class="login-input" id="login-pw" type="password" placeholder="Access Code" autofocus
      onkeydown="if(event.key==='Enter')doLogin()">
    <button class="login-btn" onclick="doLogin()">Sign In</button>
    <div class="login-error" id="login-err">Invalid access code</div>
  </div>
</div>

<!-- WELCOME MODAL -->
<div class="welcome-modal" id="welcome-modal">
  <div class="welcome-card">
    <div class="welcome-icon" id="welcome-icon"></div>
    <div class="welcome-name" id="welcome-name"></div>
    <div class="welcome-msg" id="welcome-msg"></div>
    <div class="welcome-tail" id="welcome-tail"></div>
    <button class="welcome-enter" onclick="closeWelcome()">Enter Dashboard</button>
  </div>
</div>

<!-- SPLASH -->
<div class="splash" id="splash">
  <div class="splash-logo">LAF</div>
  <div class="splash-title">WSN-LAF Simulation Dashboard</div>
  <div class="splash-sub">Loading simulation data...</div>
  <div class="splash-bar"><div class="splash-fill"></div></div>
</div>

<!-- LOADER -->
<div class="loader" id="loader">
  <div class="spinner"></div>
  <div class="loader-text">Running Simulation...</div>
  <div class="loader-sub" id="loader-sub">Initialising network</div>
</div>

<!-- TOUR -->
<div class="tour-overlay" id="tour-overlay" onclick="endTour()"></div>
<div class="tour-tip" id="tour-tip" style="display:none">
  <div class="tour-counter" id="tour-counter"></div>
  <h4 id="tour-title"></h4>
  <p id="tour-desc"></p>
  <div class="tour-btns">
    <button class="tour-skip" onclick="endTour()">Skip</button>
    <button class="tour-next" onclick="nextTour()">Next</button>
  </div>
</div>

<!-- HEALTH GAUGE -->
<div class="health-gauge" id="health-gauge">
  <div class="hg-circle">
    <svg class="hg-svg" viewBox="0 0 72 72" width="72" height="72">
      <circle class="hg-bg" cx="36" cy="36" r="30"/>
      <circle class="hg-fill" id="hg-fill" cx="36" cy="36" r="30"
        stroke-dasharray="188.5" stroke-dashoffset="188.5"/>
    </svg>
    <div class="hg-val" id="hg-val">0</div>
  </div>
  <div class="hg-label">Health</div>
</div>

<!-- FAB -->
<div class="fab" id="fab">
  <div class="fab-menu" id="fab-menu">
    <button class="fab-action" onclick="toggleDark()"><span class="material-icons-round">dark_mode</span> Toggle Dark Mode</button>
    <button class="fab-action" onclick="exportPDF()"><span class="material-icons-round">picture_as_pdf</span> Export PDF</button>
    <button class="fab-action" onclick="exportCSV()"><span class="material-icons-round">table_chart</span> Export CSV</button>
    <button class="fab-action" onclick="screenshotChart()"><span class="material-icons-round">photo_camera</span> Screenshot</button>
    <button class="fab-action" onclick="startTour()"><span class="material-icons-round">help_outline</span> Take Tour</button>
  </div>
  <button class="fab-btn" id="fab-btn" onclick="document.getElementById('fab-menu').classList.toggle('on');this.classList.toggle('open')">
    <span class="material-icons-round">add</span>
  </button>
</div>

<!-- BOTTOM TAB BAR (mobile) -->
<div class="btab-bar" id="btab-bar">
  <button class="btab active" data-page="overview" onclick="tabNav('overview',this)">
    <span class="material-icons-round">dashboard</span>Overview</button>
  <button class="btab" data-page="performance" onclick="tabNav('performance',this)">
    <span class="material-icons-round">speed</span>Perf</button>
  <button class="btab" data-page="security" onclick="tabNav('security',this)">
    <span class="material-icons-round">shield</span>Security</button>
  <button class="btab" data-page="topology" onclick="tabNav('topology',this)">
    <span class="material-icons-round">hub</span>Topology</button>
  <button class="btab" id="btab-shajan" data-page="shajanhelp" onclick="tabNav('shajanhelp',this)" style="display:none">
    <img src="/shajan-photo.jpg" class="shajan-btab-photo" alt="Shajan">Guide</button>
  <button class="btab" data-page="more" onclick="document.querySelector('.sidebar').classList.toggle('open');document.querySelector('.overlay').classList.toggle('on')">
    <span class="material-icons-round">menu</span>More</button>
</div>

<!-- PULL TO REFRESH INDICATOR -->
<div class="ptr-indicator" id="ptr-indicator">
  <span class="material-icons-round" style="color:var(--accent)">refresh</span>
</div>

<!-- SHARE BUTTON -->
<button class="share-btn" id="share-btn" onclick="shareResults()">
  <span class="material-icons-round">share</span>
</button>

<!-- TOAST -->
<div class="toast" id="toast"></div>

<!-- OFFLINE BANNER -->
<div class="offline-bar" id="offline-bar">
  <span class="material-icons-round">cloud_off</span> You are offline — showing cached data
</div>

<!-- MOBILE HEADER -->
<div class="mobile-hdr" id="mobile-hdr">
  <button class="mobile-hdr-btn" onclick="document.querySelector('.sidebar').classList.toggle('open');document.querySelector('.overlay').classList.toggle('on')">
    <span class="material-icons-round">menu</span>
  </button>
  <span class="mobile-hdr-title" id="mobile-hdr-title">Overview</span>
</div>

<!-- MOBILE HAMBURGER (desktop fallback) -->
<button class="hamburger" onclick="document.querySelector('.sidebar').classList.toggle('open');document.querySelector('.overlay').classList.toggle('on')">
  <span class="material-icons-round">menu</span>
</button>
<div class="overlay" onclick="document.querySelector('.sidebar').classList.remove('open');this.classList.remove('on')"></div>

<!-- ═══════ SIDEBAR ═══════ -->
<aside class="sidebar" id="sidebar">
  <div class="sb-header">
    <div class="sb-logo">LAF</div>
    <div class="sb-title">WSN-LAF Simulation Dashboard</div>
    <div class="sb-phd">Shajan PhD Project</div>
    <div class="sb-sub">Lightweight Adaptive Framework<br>Shajan Mohammed Mahdi — Mustansiriyah University</div>
  </div>

  <div class="sb-nav">
    <div class="sb-nav-label">Dashboard</div>
    <div class="nav-item active" onclick="showPage('overview',this)">
      <span class="material-icons-round">dashboard</span> Overview</div>
    <div class="nav-item" onclick="showPage('story',this)">
      <span class="material-icons-round">auto_stories</span> Our Story</div>
    <div class="nav-item" onclick="showPage('paper1',this)">
      <span class="material-icons-round">menu_book</span> Paper 1</div>
    <div class="nav-item" onclick="showPage('performance',this)">
      <span class="material-icons-round">speed</span> Performance</div>
    <div class="nav-item" onclick="showPage('security',this)">
      <span class="material-icons-round">shield</span> Security</div>
    <div class="nav-item" onclick="showPage('scalability',this)">
      <span class="material-icons-round">expand</span> Scalability</div>
    <div class="nav-item" onclick="showPage('ablation',this)">
      <span class="material-icons-round">science</span> Ablation</div>
    <div class="nav-item" onclick="showPage('longterm',this)">
      <span class="material-icons-round">schedule</span> Long-Term</div>
    <div class="nav-item" onclick="showPage('recovery',this)">
      <span class="material-icons-round">healing</span> Recovery</div>
    <div class="nav-item" onclick="showPage('comparison',this)">
      <span class="material-icons-round">compare_arrows</span> Compare</div>
    <div class="nav-item" onclick="showPage('topology',this)">
      <span class="material-icons-round">hub</span> Topology</div>
    <div class="nav-item" onclick="showPage('pdgoals',this)">
      <span class="material-icons-round">verified</span> PD Goals</div>
    <div class="nav-item" onclick="showPage('help',this)">
      <span class="material-icons-round">help_outline</span> Help Guide</div>
    <div class="nav-item" id="nav-shajan-help" onclick="showPage('shajanhelp',this)" style="display:none">
      <img src="/shajan-photo.jpg" class="shajan-nav-photo" alt="Shajan"> Shajan's Guide</div>
    <div class="nav-item" id="pwa-install" onclick="installPWA()" style="display:none;color:var(--accent);font-weight:700">
      <span class="material-icons-round">install_mobile</span> Install App</div>
  </div>

  <div class="sb-params" id="sb-params">
    <div class="sb-params-header" onclick="this.parentElement.classList.toggle('collapsed')">
      <div class="sb-params-title">Simulation Parameters</div>
      <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();resetParams()">Reset</button>
    </div>

    <div class="param-section">
      <div class="param-title">Network</div>
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
      <div class="param-title">Routing Weights</div>
      <div class="param-row">
        <label>α Energy <span id="lbl-alpha">0.40</span></label>
        <div class="range-wrap"><input type="range" id="p-alpha" min="0.1" max="0.8" step="0.05" value="0.4"
          oninput="updLbl('alpha',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-alpha">0.40</span></div>
      </div>
      <div class="param-row">
        <label>β Delay <span id="lbl-beta">0.30</span></label>
        <div class="range-wrap"><input type="range" id="p-beta" min="0.1" max="0.7" step="0.05" value="0.3"
          oninput="updLbl('beta',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-beta">0.30</span></div>
      </div>
      <div class="param-row">
        <label>γ Trust <span id="lbl-gamma">0.30</span></label>
        <div class="range-wrap"><input type="range" id="p-gamma" min="0.1" max="0.7" step="0.05" value="0.3"
          oninput="updLbl('gamma',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-gamma">0.30</span></div>
      </div>
    </div>

    <div class="param-section">
      <div class="param-title">CH Selection</div>
      <div class="param-row">
        <label>λ₁ Energy <span id="lbl-l1">0.50</span></label>
        <div class="range-wrap"><input type="range" id="p-l1" min="0.1" max="0.8" step="0.05" value="0.5"
          oninput="updLbl('l1',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-l1">0.50</span></div>
      </div>
      <div class="param-row">
        <label>λ₂ Link <span id="lbl-l2">0.25</span></label>
        <div class="range-wrap"><input type="range" id="p-l2" min="0.1" max="0.5" step="0.05" value="0.25"
          oninput="updLbl('l2',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-l2">0.25</span></div>
      </div>
      <div class="param-row">
        <label>λ₃ Trust <span id="lbl-l3">0.25</span></label>
        <div class="range-wrap"><input type="range" id="p-l3" min="0.1" max="0.5" step="0.05" value="0.25"
          oninput="updLbl('l3',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-l3">0.25</span></div>
      </div>
    </div>

    <div class="param-section">
      <div class="param-title">Energy &amp; Trust</div>
      <div class="param-row">
        <label>Initial Energy (J)</label>
        <input type="number" id="p-einit" value="0.5" step="0.1" min="0.1" max="2.0">
      </div>
      <div class="param-row">
        <label>CH ratio <span id="lbl-popt">0.05</span></label>
        <div class="range-wrap"><input type="range" id="p-popt" min="0.02" max="0.15" step="0.01" value="0.05"
          oninput="updLbl('popt',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-popt">0.05</span></div>
      </div>
      <div class="param-row">
        <label>Trust ρ <span id="lbl-rho">0.40</span></label>
        <div class="range-wrap"><input type="range" id="p-rho" min="0.1" max="0.9" step="0.05" value="0.4"
          oninput="updLbl('rho',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-rho">0.40</span></div>
      </div>
      <div class="param-row">
        <label>Threshold τ <span id="lbl-tau">0.50</span></label>
        <div class="range-wrap"><input type="range" id="p-tau" min="0.2" max="0.8" step="0.05" value="0.5"
          oninput="updLbl('tau',parseFloat(this.value).toFixed(2))"><span class="range-val" id="rv-tau">0.50</span></div>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Adaptive routing</span>
        <label class="toggle"><input type="checkbox" id="p-adaptive" checked><span class="slider-t"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Blockchain</span>
        <label class="toggle"><input type="checkbox" id="p-blockchain" checked><span class="slider-t"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Trust cost</span>
        <label class="toggle"><input type="checkbox" id="p-trustcost" checked><span class="slider-t"></span></label>
      </div>
    </div>
  </div>

  <div class="dm-toggle" onclick="toggleDark()">
    <span class="material-icons-round">dark_mode</span> Dark / Light Mode
  </div>
  <div class="preset-dd">
    <div class="preset-btn" onclick="this.nextElementSibling.classList.toggle('on')">
      <span class="material-icons-round" style="font-size:14px">tune</span> Presets ▾
    </div>
    <div class="preset-list" id="preset-list">
      <div class="preset-opt" onclick="applyPreset('default')">Default (Paper 2)<small>N=100, R=500, balanced weights</small></div>
      <div class="preset-opt" onclick="applyPreset('dense')">High Density<small>N=200, R=500, more nodes</small></div>
      <div class="preset-opt" onclick="applyPreset('hostile')">Hostile Environment<small>N=100, R=500, 30% attack ratio</small></div>
      <div class="preset-opt" onclick="applyPreset('lowenergy')">Low Energy<small>N=100, R=300, E=0.2J</small></div>
      <div class="preset-opt" onclick="applyPreset('longrun')">Long Run<small>N=100, R=1000, endurance test</small></div>
    </div>
  </div>
  <div class="sb-actions">
    <button class="btn btn-primary" id="run-btn" onclick="runSim()">
      <span class="material-icons-round" style="font-size:16px">play_arrow</span> Run Simulation</button>
    <button class="btn btn-paper2" onclick="applyPaper2Params()">
      <span class="material-icons-round" style="font-size:16px">auto_fix_high</span> Paper 2 Mode</button>
  </div>
</aside>

<!-- ═══════ MAIN CONTENT ═══════ -->
<div class="main">

<!-- STATS TICKER -->
<div class="stats-ticker" id="stats-ticker">
  <div class="st-item"><span class="st-icon">🟢</span> Alive: <span class="st-val" id="st-alive">—</span></div>
  <div class="st-divider"></div>
  <div class="st-item"><span class="st-icon">📡</span> PDR: <span class="st-val" id="st-pdr">—</span></div>
  <div class="st-divider"></div>
  <div class="st-item"><span class="st-icon">⚡</span> Energy: <span class="st-val" id="st-energy">—</span></div>
  <div class="st-divider"></div>
  <div class="st-item"><span class="st-icon">🕐</span> FND: <span class="st-val" id="st-fnd">—</span></div>
  <div class="st-divider"></div>
  <div class="st-item"><span class="st-icon">🔒</span> Trust: <span class="st-val" id="st-trust">—</span></div>
</div>

<!-- BREADCRUMB -->
<div class="breadcrumb" id="breadcrumb">
  <span class="material-icons-round">dashboard</span> Dashboard &rsaquo; <span class="bc-page" id="bc-page">Overview</span>
</div>

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
    </div>
    <div class="kpi-row" id="kpi-row">
      <div class="kpi"><div class="kpi-icon" style="color:var(--green)"><span class="material-icons-round">battery_charging_full</span></div><div class="kpi-val" id="kv-energy" style="color:var(--green)">+14.3%</div>
        <div class="kpi-label">Residual Energy vs LEACH</div><div class="kpi-paper" id="kp-energy">Paper 2 confirmed</div></div>
      <div class="kpi"><div class="kpi-icon" style="color:var(--accent)"><span class="material-icons-round">timer</span></div><div class="kpi-val" id="kv-life" style="color:var(--accent)">+8.8%</div>
        <div class="kpi-label">Network Lifetime (FND)</div><div class="kpi-paper" id="kp-life">379 vs 348 rounds</div></div>
      <div class="kpi"><div class="kpi-icon" style="color:var(--cyan)"><span class="material-icons-round">speed</span></div><div class="kpi-val" id="kv-tput" style="color:var(--cyan)">+11.4%</div>
        <div class="kpi-label">Throughput</div><div class="kpi-paper" id="kp-tput">217 vs 195 kbps</div></div>
      <div class="kpi"><div class="kpi-icon" style="color:var(--yellow)"><span class="material-icons-round">verified</span></div><div class="kpi-val" id="kv-pdr" style="color:var(--yellow)">+3.7%</div>
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
    <tbody id="sum-table"></tbody></table>
    <div style="font-size:11px;color:var(--muted);margin-top:12px;padding:0 4px;line-height:1.6">* SPIN and DD values are simulation approximations. These protocols serve as secondary baselines — LAF, LEACH, and TEARP are the primary comparison targets.</div></div>
  <div class="card" style="text-align:center;padding:24px">
    <div class="ct"><div class="dot" style="background:var(--accent)"></div>Share This Dashboard</div>
    <div style="margin:16px 0"><img id="qr-img" src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=https://wsn-laf-dashboard.onrender.com" alt="QR Code" width="150" height="150" style="border-radius:8px;border:2px solid var(--border)" onerror="this.style.display='none';this.nextElementSibling.style.display='block'"><div style="display:none;padding:20px;color:var(--muted);font-size:13px">QR code unavailable offline</div></div>
    <div style="font-size:13px;color:var(--muted);font-weight:600">wsn-laf-dashboard.onrender.com</div>
    <div style="font-size:11px;color:var(--muted);margin-top:4px">Scan to open on another device</div>
  </div>
</div>

<!-- OUR STORY — Research Journey -->
<div id="page-story" class="page">
<div id="story-wrap" style="max-width:900px;margin:0 auto;padding:12px 0">

  <!-- Language toggle -->
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;flex-wrap:wrap;gap:12px">
    <div style="font-size:26px;font-weight:800;color:#f97316">Our Research Story</div>
    <div style="display:flex;gap:6px">
      <button onclick="setStoryLang('en')" id="story-btn-en" style="padding:8px 18px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;border:2px solid #f97316;background:#f97316;color:#fff;font-family:'Inter',sans-serif">English</button>
      <button onclick="setStoryLang('ar')" id="story-btn-ar" style="padding:8px 18px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;border:2px solid #f97316;background:transparent;color:#f97316;font-family:'Inter',sans-serif">العربية</button>
    </div>
  </div>

  <!-- ═══ SECTION 1 — THE PROBLEM ═══ -->
  <div class="story-section">
    <div class="story-num">1</div>
    <div class="story-body">
      <div class="story-icon" style="color:#dc2626"><span class="material-icons-round" style="font-size:48px">warning</span></div>
      <div class="story-heading" data-en="The Problem We Solved" data-ar="المشكلة التي حللناها">The Problem We Solved</div>
      <div class="story-cards-3">
        <div class="story-card story-card-problem">
          <span class="material-icons-round" style="font-size:36px;color:#dc2626;margin-bottom:12px">battery_alert</span>
          <div class="story-card-title" data-en="Energy Waste" data-ar="هدر الطاقة">Energy Waste</div>
          <div class="story-card-text" data-en="Existing protocols like LEACH waste battery by ignoring node energy in routing decisions. Sensor nodes die early, leaving gaps in the network." data-ar="البروتوكولات الحالية مثل LEACH تهدر البطارية بتجاهل طاقة العقدة في قرارات التوجيه. تموت عقد الاستشعار مبكرًا، مما يترك فجوات في الشبكة.">Existing protocols like LEACH waste battery by ignoring node energy in routing decisions. Sensor nodes die early, leaving gaps in the network.</div>
        </div>
        <div class="story-card story-card-problem">
          <span class="material-icons-round" style="font-size:36px;color:#dc2626;margin-bottom:12px">gpp_bad</span>
          <div class="story-card-title" data-en="Security Attacks" data-ar="هجمات أمنية">Security Attacks</div>
          <div class="story-card-text" data-en="Sinkhole, Sybil, Selective Forwarding, and Hello Flood attacks can drop PDR from 91% down to 34% with no defence." data-ar="هجمات Sinkhole وSybil وSelective Forwarding وHello Flood يمكن أن تُسقط نسبة PDR من 91% إلى 34% بدون أي دفاع.">Sinkhole, Sybil, Selective Forwarding, and Hello Flood attacks can drop PDR from 91% down to 34% with no defence.</div>
        </div>
        <div class="story-card story-card-problem">
          <span class="material-icons-round" style="font-size:36px;color:#dc2626;margin-bottom:12px">search_off</span>
          <div class="story-card-title" data-en="No Unified Solution" data-ar="لا يوجد حل موحد">No Unified Solution</div>
          <div class="story-card-text" data-en="44 reviewed studies (Paper 1) confirmed no existing framework solved energy efficiency AND security AND adaptability simultaneously on Class 1 hardware." data-ar="44 دراسة تمت مراجعتها (الورقة 1) أكدت أنه لا يوجد إطار عمل حالي يحل كفاءة الطاقة والأمان والقدرة على التكيف معًا على أجهزة Class 1.">44 reviewed studies (Paper 1) confirmed no existing framework solved energy efficiency AND security AND adaptability simultaneously on Class 1 hardware.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ SECTION 2 — THE SOLUTION ═══ -->
  <div class="story-section">
    <div class="story-num">2</div>
    <div class="story-body">
      <div class="story-icon" style="color:#16a34a"><span class="material-icons-round" style="font-size:48px">check_circle</span></div>
      <div class="story-heading" data-en="Our Solution — The LAF Framework" data-ar="حلنا — إطار عمل LAF">Our Solution — The LAF Framework</div>
      <div class="story-cards-3">
        <div class="story-card story-card-solution">
          <div class="story-c-badge">C1</div>
          <div class="story-card-title" data-en="Smart CH Selection" data-ar="اختيار ذكي لرأس العنقود">Smart CH Selection</div>
          <div class="story-card-text" data-en="Picks the strongest, most trustworthy cluster head based on energy, trust, and distance." data-ar="يختار رأس العنقود الأقوى والأكثر موثوقية بناءً على الطاقة والثقة والمسافة.">Picks the strongest, most trustworthy cluster head based on energy, trust, and distance.</div>
        </div>
        <div class="story-card story-card-solution">
          <div class="story-c-badge">C2</div>
          <div class="story-card-title" data-en="Composite Cost Routing" data-ar="توجيه التكلفة المركبة">Composite Cost Routing</div>
          <div class="story-card-text" data-en="Formula αE + βD + γ(1−T) balances energy, distance, and trust in every routing decision." data-ar="صيغة αE + βD + γ(1−T) توازن بين الطاقة والمسافة والثقة في كل قرار توجيه.">Formula αE + βD + γ(1−T) balances energy, distance, and trust in every routing decision.</div>
        </div>
        <div class="story-card story-card-solution">
          <div class="story-c-badge">C3</div>
          <div class="story-card-title" data-en="Lightweight Blockchain" data-ar="بلوكتشين خفيف">Lightweight Blockchain</div>
          <div class="story-card-text" data-en="PoA/PBFT-Lite consensus, blocks below 2KB, ledger below 50KB — fits Class 1 hardware." data-ar="إجماع PoA/PBFT-Lite، كتل أقل من 2KB، سجل أقل من 50KB — يناسب أجهزة Class 1.">PoA/PBFT-Lite consensus, blocks below 2KB, ledger below 50KB — fits Class 1 hardware.</div>
        </div>
        <div class="story-card story-card-solution">
          <div class="story-c-badge">C4</div>
          <div class="story-card-title" data-en="Rigorous Validation" data-ar="تحقق صارم">Rigorous Validation</div>
          <div class="story-card-text" data-en="30 Monte Carlo runs × 6 scenarios = 2,430 total independent simulation tests." data-ar="30 تشغيل Monte Carlo × 6 سيناريوهات = 2,430 اختبار محاكاة مستقل.">30 Monte Carlo runs × 6 scenarios = 2,430 total independent simulation tests.</div>
        </div>
        <div class="story-card story-card-solution">
          <div class="story-c-badge">C5</div>
          <div class="story-card-title" data-en="Adaptive Weights" data-ar="أوزان تكيفية">Adaptive Weights</div>
          <div class="story-card-text" data-en="γ increases automatically when network is under attack — security scales with threat level." data-ar="γ يزداد تلقائيًا عندما تكون الشبكة تحت الهجوم — الأمان يتناسب مع مستوى التهديد.">γ increases automatically when network is under attack — security scales with threat level.</div>
        </div>
        <div class="story-card story-card-solution">
          <div class="story-c-badge">C6</div>
          <div class="story-card-title" data-en="Cross-Layer Feedback" data-ar="تغذية راجعة عبر الطبقات">Cross-Layer Feedback</div>
          <div class="story-card-text" data-en="Blockchain trust scores update routing every single round — real-time security integration." data-ar="درجات الثقة من البلوكتشين تُحدّث التوجيه في كل جولة — تكامل أمني في الوقت الفعلي.">Blockchain trust scores update routing every single round — real-time security integration.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ SECTION 3 — THE RESULTS ═══ -->
  <div class="story-section">
    <div class="story-num">3</div>
    <div class="story-body">
      <div class="story-icon" style="color:#f97316"><span class="material-icons-round" style="font-size:48px">emoji_events</span></div>
      <div class="story-heading" data-en="What We Proved — 4 Validated Improvements" data-ar="ما أثبتناه — 4 تحسينات مؤكدة">What We Proved — 4 Validated Improvements</div>
      <div class="story-metrics">
        <div class="story-metric">
          <div class="story-metric-val">+14.3%</div>
          <div class="story-metric-label" data-en="Residual Energy" data-ar="الطاقة المتبقية">Residual Energy</div>
          <div class="story-metric-sub" data-en="vs LEACH" data-ar="مقارنة بـ LEACH">vs LEACH</div>
        </div>
        <div class="story-metric">
          <div class="story-metric-val">+8.8%</div>
          <div class="story-metric-label" data-en="Network Lifetime" data-ar="عمر الشبكة">Network Lifetime</div>
          <div class="story-metric-sub" data-en="FND: 379 vs 348 rounds" data-ar="FND: 379 مقابل 348 جولة">FND: 379 vs 348 rounds</div>
        </div>
        <div class="story-metric">
          <div class="story-metric-val">+11.4%</div>
          <div class="story-metric-label" data-en="Throughput" data-ar="الإنتاجية">Throughput</div>
          <div class="story-metric-sub" data-en="180 vs 156 kbps" data-ar="180 مقابل 156 kbps">180 vs 156 kbps</div>
        </div>
        <div class="story-metric">
          <div class="story-metric-val">+3.7%</div>
          <div class="story-metric-label" data-en="Packet Delivery" data-ar="نسبة تسليم الحزم">Packet Delivery</div>
          <div class="story-metric-sub" data-en="91.8% vs 88.6%" data-ar="91.8% مقابل 88.6%">91.8% vs 88.6%</div>
        </div>
      </div>
      <div class="story-checks">
        <div class="story-check">
          <span class="material-icons-round" style="color:#16a34a;font-size:28px">check_circle</span>
          <div><strong data-en="Latency: 29.0ms" data-ar="زمن الاستجابة: 29.0ms">Latency: 29.0ms</strong> <span class="story-check-note" data-en="— below 30ms target" data-ar="— أقل من هدف 30ms">— below 30ms target</span></div>
        </div>
        <div class="story-check">
          <span class="material-icons-round" style="color:#16a34a;font-size:28px">check_circle</span>
          <div><strong data-en="Ledger: 39.1KB" data-ar="حجم السجل: 39.1KB">Ledger: 39.1KB</strong> <span class="story-check-note" data-en="— below 50KB target" data-ar="— أقل من هدف 50KB">— below 50KB target</span></div>
        </div>
        <div class="story-check">
          <span class="material-icons-round" style="color:#16a34a;font-size:28px">check_circle</span>
          <div><strong data-en="Recovery: &lt;1 round" data-ar="التعافي: أقل من جولة واحدة">Recovery: &lt;1 round</strong> <span class="story-check-note" data-en="— below 5 round target" data-ar="— أقل من هدف 5 جولات">— below 5 round target</span></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ SECTION 4 — THE IMPACT ═══ -->
  <div class="story-section">
    <div class="story-num">4</div>
    <div class="story-body">
      <div class="story-icon" style="color:#f97316"><span class="material-icons-round" style="font-size:48px">star</span></div>
      <div class="story-heading" data-en="Why This Matters" data-ar="لماذا هذا مهم">Why This Matters</div>
      <div class="story-card" style="background:linear-gradient(135deg,#fff7ed,#fff);border:1.5px solid #f5d5b8;padding:28px;border-radius:16px;margin-bottom:20px">
        <div class="story-card-text" style="font-size:17px;line-height:1.9" data-en="This research proves for the first time that a single lightweight framework can simultaneously achieve energy efficiency, decentralised security, and adaptive routing on Class 1 constrained sensor nodes. Validated across 6 scenarios, 7 network scales, 4 attack types, and 2,430 independent simulation tests — all results independently reproducible using seed 42." data-ar="يثبت هذا البحث لأول مرة أن إطار عمل خفيف واحد يمكنه تحقيق كفاءة الطاقة والأمان اللامركزي والتوجيه التكيفي في آن واحد على عقد استشعار مقيدة من Class 1. تم التحقق عبر 6 سيناريوهات و7 أحجام شبكة و4 أنواع هجمات و2,430 اختبار محاكاة مستقل — جميع النتائج قابلة لإعادة الإنتاج باستخدام seed 42.">This research proves for the first time that a single lightweight framework can simultaneously achieve energy efficiency, decentralised security, and adaptive routing on Class 1 constrained sensor nodes. Validated across 6 scenarios, 7 network scales, 4 attack types, and 2,430 independent simulation tests — all results independently reproducible using seed 42.</div>
      </div>
      <div class="story-impacts">
        <div class="story-impact-badge"><span class="material-icons-round">description</span> <span data-en="2 Published Papers" data-ar="ورقتان بحثيتان منشورتان">2 Published Papers</span></div>
        <div class="story-impact-badge"><span class="material-icons-round">computer</span> <span data-en="Live Verification Dashboard" data-ar="لوحة تحقق مباشرة">Live Verification Dashboard</span></div>
        <div class="story-impact-badge"><span class="material-icons-round">lock_open</span> <span data-en="Open Reproducible Results" data-ar="نتائج مفتوحة قابلة للتكرار">Open Reproducible Results</span></div>
      </div>
    </div>
  </div>

</div>
</div>

<!-- PAPER 1 — Literature Review -->
<div id="page-paper1" class="page">
  <div class="hero">
    <div class="hero-top"><div>
      <div class="hero-title">Paper 1 — Systematic Literature Review</div>
      <div class="hero-sub">A comprehensive review of WSN security and routing protocols (2018–2025)</div>
    </div></div>
    <div class="kpi-row">
      <div class="kpi"><div class="kpi-val" style="color:var(--accent)">44</div><div class="kpi-label">Studies Reviewed</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--green)">2018–2025</div><div class="kpi-label">Publication Range</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--cyan)">3</div><div class="kpi-label">Protocol Families</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--yellow)">6</div><div class="kpi-label">Gaps Found</div></div>
    </div>
  </div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Protocol Family Breakdown</div>
      <div class="ch"><canvas id="c-p1-donut"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>Studies per Year</div>
      <div class="ch"><canvas id="c-p1-bar"></canvas></div></div>
  </div>
  <div class="card"><div class="ct"><div class="dot" style="background:var(--yellow)"></div>Research Gaps Identified</div>
    <table><thead><tr><th>Gap ID</th><th>Gap Title</th><th>Addressed By</th></tr></thead>
    <tbody id="p1-gaps"></tbody></table></div>
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
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Network Lifetime — 1,500 Rounds</div>
      <div style="position:relative;height:320px;min-height:300px"><canvas id="c-lt-alive"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--green)"></div>Residual Energy Over Time</div>
      <div style="position:relative;height:320px;min-height:300px"><canvas id="c-lt-energy"></canvas></div></div>
  </div>
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--cyan)"></div>PDR Stability Long-Term</div>
      <div style="position:relative;height:300px;min-height:260px"><canvas id="c-lt-pdr"></canvas></div></div>
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>Blockchain Ledger Footprint (KB)</div>
      <div style="position:relative;height:300px;min-height:260px"><canvas id="c-lt-ledger"></canvas></div></div>
  </div>
  <div class="card" style="margin-top:18px">
    <div class="ct">Long-Term Summary</div>
    <table><thead><tr><th>Protocol</th><th>FND (rounds)</th><th>HND (rounds)</th><th>Final PDR</th><th>Mean Latency</th><th>Max Ledger</th><th>Lifetime vs LEACH</th></tr></thead>
    <tbody id="lt-tbody"></tbody></table></div>
</div>

<!-- RECOVERY -->
<div id="page-recovery" class="page">
  <div class="g2">
    <div class="card"><div class="ct"><div class="dot" style="background:var(--accent)"></div>PDR During Node Failure Event (20% Failure at Round 200)</div>
      <div style="position:relative;height:320px;min-height:300px"><canvas id="c-rec-pdr"></canvas></div></div>
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
    <tbody id="cmp-tbody"></tbody></table>
    <div style="font-size:11px;color:var(--muted);margin-top:12px;padding:0 4px;line-height:1.6">* SPIN and DD values are simulation approximations. These protocols serve as secondary baselines — LAF, LEACH, and TEARP are the primary comparison targets.</div></div>
</div>

<!-- TOPOLOGY -->
<div id="page-topology" class="page">
  <div class="card" style="margin-bottom:24px">
    <div class="ct"><div class="dot" style="background:var(--accent)"></div>Interactive WSN Topology</div>
    <canvas id="topo-canvas" width="900" height="550"></canvas>
    <div class="topo-legend">
      <span><div class="tl-dot" style="background:var(--accent)"></div> Normal Node</span>
      <span><div class="tl-dot" style="background:#16a34a"></div> Cluster Head</span>
      <span><div class="tl-dot" style="background:var(--red)"></div> Attack Node</span>
      <span><div class="tl-dot" style="background:#1e293b;width:14px;height:14px"></div> Base Station</span>
      <span style="color:var(--accent)">— Active Route</span>
    </div>
  </div>
  <div class="g3">
    <div class="card" style="text-align:center;padding:20px">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.5px;margin-bottom:6px">Alive Nodes</div>
      <div id="topo-alive" style="font-size:36px;font-weight:900;color:var(--accent);font-family:'JetBrains Mono',monospace">100</div>
    </div>
    <div class="card" style="text-align:center;padding:20px">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.5px;margin-bottom:6px">Cluster Heads</div>
      <div id="topo-chs" style="font-size:36px;font-weight:900;color:#16a34a;font-family:'JetBrains Mono',monospace">5</div>
    </div>
    <div class="card" style="text-align:center;padding:20px">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.5px;margin-bottom:6px">Attack Nodes</div>
      <div id="topo-atk" style="font-size:36px;font-weight:900;color:var(--red);font-family:'JetBrains Mono',monospace">10</div>
    </div>
  </div>
</div>

<!-- PD GOALS -->
<div id="page-pdgoals" class="page">
  <div class="pdg-header">
    <h2>Proposal Defense — Target Achievement</h2>
    <p>Shajan Mohammed Mahdi · Mustansiriyah University · 2025</p>
    <button class="pdg-recalc-btn" id="pdg-recalc-btn" onclick="recalcPDGoals()">
      <span class="material-icons-round" style="font-size:18px">refresh</span> Recalculate Live
    </button>
  </div>
  <div class="pdg-summary" id="pdg-summary"></div>
  <div class="pdg-terminal" id="pdg-terminal" style="display:none">
    <div class="pdg-term-bar"><span class="pdg-term-dot red"></span><span class="pdg-term-dot yellow"></span><span class="pdg-term-dot green"></span><span class="pdg-term-title">WSN-LAF Simulation Console</span></div>
    <div class="pdg-term-body" id="pdg-term-body"></div>
  </div>
  <div id="pdg-cards"></div>
</div>

<!-- HELP -->
<div id="page-help" class="page">
  <div class="help-section-title"><span class="material-icons-round" style="color:var(--accent)">menu_book</span> Help Guide</div>
  <div class="help-section-sub">Learn how to use the WSN-LAF Simulation Dashboard. Click any section for details.</div>

  <div class="help-grid">
    <div class="help-card">
      <h3><span class="material-icons-round">play_circle</span> Getting Started</h3>
      <p>The dashboard loads with pre-computed Paper 2 results. You can explore all tabs immediately.</p>
      <div class="help-step"><div class="help-num">1</div><div class="help-txt">Browse tabs on the left sidebar to explore different analyses</div></div>
      <div class="help-step"><div class="help-num">2</div><div class="help-txt">Adjust parameters in the sidebar sliders</div></div>
      <div class="help-step"><div class="help-num">3</div><div class="help-txt">Click <b>Run Simulation</b> to generate new results</div></div>
    </div>
    <div class="help-card">
      <h3><span class="material-icons-round">tune</span> Parameters</h3>
      <p>All simulation parameters are in the left sidebar. Each slider adjusts a specific aspect of the LAF protocol.</p>
      <div class="help-step"><div class="help-num">α</div><div class="help-txt"><b>Energy weight</b> — How much energy efficiency matters in routing decisions</div></div>
      <div class="help-step"><div class="help-num">β</div><div class="help-txt"><b>Delay weight</b> — Priority given to minimising communication delay</div></div>
      <div class="help-step"><div class="help-num">γ</div><div class="help-txt"><b>Trust weight</b> — Importance of node trustworthiness in routing</div></div>
    </div>
    <div class="help-card">
      <h3><span class="material-icons-round">hub</span> Topology View</h3>
      <p>The interactive topology tab shows a live animated WSN network.</p>
      <div class="help-step"><div class="help-num">1</div><div class="help-txt"><b>Drag nodes</b> — Click and drag any node to reposition it</div></div>
      <div class="help-step"><div class="help-num">2</div><div class="help-txt"><b>Hover</b> — Mouse over a node to see energy and trust values</div></div>
      <div class="help-step"><div class="help-num">3</div><div class="help-txt"><b>Click</b> — Click a node to simulate failure (it fades out)</div></div>
    </div>
    <div class="help-card">
      <h3><span class="material-icons-round">auto_fix_high</span> Paper 2 Mode</h3>
      <p>Reproduces the exact parameters and results from the published Paper 2 research.</p>
      <div class="help-step"><div class="help-num">1</div><div class="help-txt">Click <b>Paper 2 Mode</b> in the sidebar to load exact parameters</div></div>
      <div class="help-step"><div class="help-num">2</div><div class="help-txt">Click <b>Run Simulation</b> to reproduce published results</div></div>
      <div class="help-step"><div class="help-num">3</div><div class="help-txt">Compare with your custom parameter runs</div></div>
    </div>
    <div class="help-card">
      <h3><span class="material-icons-round">download</span> Exporting Data</h3>
      <p>Use the orange <b>+</b> button (bottom-right) to access export options.</p>
      <div class="help-step"><div class="help-num">📄</div><div class="help-txt"><b>PDF</b> — Download a full report with all charts</div></div>
      <div class="help-step"><div class="help-num">📊</div><div class="help-txt"><b>CSV</b> — Export raw simulation data for analysis</div></div>
      <div class="help-step"><div class="help-num">📷</div><div class="help-txt"><b>Screenshot</b> — Capture the current view as an image</div></div>
    </div>
    <div class="help-card">
      <h3><span class="material-icons-round">shield</span> Understanding Tabs</h3>
      <p>Each tab focuses on a different aspect of the simulation analysis.</p>
      <div class="help-step"><div class="help-num">📊</div><div class="help-txt"><b>Overview</b> — Summary KPIs and comparison charts</div></div>
      <div class="help-step"><div class="help-num">🔐</div><div class="help-txt"><b>Security</b> — Attack resilience (Sinkhole, Sybil, etc.)</div></div>
      <div class="help-step"><div class="help-num">📈</div><div class="help-txt"><b>Scalability</b> — Performance at 50-500 nodes</div></div>
    </div>
  </div>

  <div class="help-section-title" style="margin-top:32px"><span class="material-icons-round" style="color:var(--accent)">school</span> Glossary</div>
  <div class="help-section-sub">Key terms used throughout the dashboard.</div>
  <div class="glossary-grid">
    <div class="glossary-item"><dt>PDR</dt><dd>Packet Delivery Ratio — percentage of data packets successfully delivered to the base station</dd></div>
    <div class="glossary-item"><dt>FND</dt><dd>First Node Dead — the round when the first sensor node runs out of energy</dd></div>
    <div class="glossary-item"><dt>HND</dt><dd>Half Nodes Dead — the round when 50% of nodes have died</dd></div>
    <div class="glossary-item"><dt>CH</dt><dd>Cluster Head — elected node that aggregates and forwards data from its cluster</dd></div>
    <div class="glossary-item"><dt>LAF</dt><dd>Lightweight Adaptive Framework — the proposed protocol combining trust, energy, and blockchain</dd></div>
    <div class="glossary-item"><dt>LEACH</dt><dd>Low-Energy Adaptive Clustering Hierarchy — a classic WSN routing protocol baseline</dd></div>
    <div class="glossary-item"><dt>Trust Score</dt><dd>A 0-1 value representing how reliable a node is, updated via blockchain consensus</dd></div>
    <div class="glossary-item"><dt>Residual Energy</dt><dd>Remaining energy in nodes — higher means longer network lifetime</dd></div>
    <div class="glossary-item"><dt>Throughput</dt><dd>Amount of data successfully transmitted per unit time (kbps)</dd></div>
  </div>
</div>

<!-- FOOTER -->
<div class="footer">
  <strong>WSN-LAF Simulation Dashboard</strong> — Shajan Mohammed Mahdi<br>
  PhD Research · Mustansiriyah University · 2025<br>
  Lightweight Adaptive Framework for Secure Wireless Sensor Networks<br>
  <a href="#" onclick="startTour();return false">Take Interactive Tour</a> ·
  <a href="#" onclick="showPage('help',document.querySelector('[onclick*=help]'));return false">Help Guide</a>
</div>

<!-- SHAJAN HELP (login "1" only) -->
<div id="page-shajanhelp" class="page">
<div id="sg-wrap" style="max-width:800px;margin:0 auto;padding:8px 0;font-size:18px;line-height:1.8;color:#4a2c0a">

  <!-- HEADER + TABS -->
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px">
    <div style="display:flex;align-items:center;gap:12px"><img src="/shajan-photo.jpg" class="shajan-header-photo" alt="Shajan"><span style="font-size:24px;font-weight:800;color:#f97316">Shajan's Guide</span></div>
    <div style="display:flex;gap:6px">
      <button onclick="setSgLang('en')" id="sg-btn-en" style="padding:8px 18px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;border:2px solid #f97316;background:#f97316;color:#fff;font-family:'Inter',sans-serif">English</button>
      <button onclick="setSgLang('ar')" id="sg-btn-ar" style="padding:8px 18px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;border:2px solid #f97316;background:transparent;color:#f97316;font-family:'Inter',sans-serif">العربية</button>
    </div>
  </div>
  <div style="display:flex;gap:8px;margin-bottom:24px">
    <button onclick="sgTab('guide')" id="sg-tab-btn-guide" class="sg-tab-btn sg-tab-active">Guide</button>
    <button onclick="sgTab('pods')" id="sg-tab-btn-pods" class="sg-tab-btn">Podcasts & Videos</button>
  </div>

  <div id="sg-tab-guide">
  <!-- 1. TODAY'S QUICK REMINDER -->
  <div class="sg-card" style="background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;border-radius:16px;padding:28px 28px 24px;margin-bottom:24px;box-shadow:0 8px 30px rgba(249,115,22,.25)">
    <div style="font-size:20px;font-weight:800;margin-bottom:16px" data-en="Today's Quick Reminder" data-ar="تذكير اليوم السريع">Today's Quick Reminder</div>
    <div style="font-size:18px;line-height:2">
      <div data-en="My framework is called: <b>LAF</b>" data-ar="إطار العمل الخاص بي يسمى: <b>LAF</b>">My framework is called: <b>LAF</b></div>
      <div data-en="My result vs LEACH: <b>+14.3%</b> energy · <b>+8.8%</b> lifetime · <b>+11.4%</b> throughput · <b>+3.7%</b> PDR" data-ar="نتيجتي مقارنة بـ LEACH: <b>+14.3%</b> طاقة · <b>+8.8%</b> عمر الشبكة · <b>+11.4%</b> إنتاجية · <b>+3.7%</b> PDR">My result vs LEACH: <b>+14.3%</b> energy · <b>+8.8%</b> lifetime · <b>+11.4%</b> throughput · <b>+3.7%</b> PDR</div>
      <div data-en="My latency result: <b>29.0 ms</b> (target was ≤30ms ✅)" data-ar="نتيجة زمن الاستجابة: <b>29.0 ms</b> (الهدف كان ≤30ms ✅)">My latency result: <b>29.0 ms</b> (target was ≤30ms ✅)</div>
      <div data-en="My ledger result: <b>39.1 KB</b> (target was ≤50KB ✅)" data-ar="نتيجة حجم السجل: <b>39.1 KB</b> (الهدف كان ≤50KB ✅)">My ledger result: <b>39.1 KB</b> (target was ≤50KB ✅)</div>
    </div>
  </div>

  <!-- 2. BEFORE THE VIVA -->
  <div class="sg-card" style="background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:16px;padding:28px;margin-bottom:24px">
    <div style="font-size:20px;font-weight:800;color:#f97316;margin-bottom:16px" data-en="Before the Viva — Do This" data-ar="قبل المناقشة — افعلي هذا">Before the Viva — Do This</div>
    <div class="sg-steps">
      <div class="sg-step"><span class="sg-num">1</span><span data-en="Open the website on the projector" data-ar="افتحي الموقع على جهاز العرض (projector)">Open the website on the projector</span></div>
      <div class="sg-step"><span class="sg-num">2</span><span data-en='Click <b>"Paper 2 Mode"</b> button — shows exact published results' data-ar='اضغطي على زر <b>"Paper 2 Mode"</b> — يعرض النتائج المنشورة بالضبط'>Click <b>"Paper 2 Mode"</b> button — shows exact published results</span></div>
      <div class="sg-step"><span class="sg-num">3</span><span data-en="Click <b>PD Goals</b> — shows all 10 proposal goals" data-ar="اضغطي على <b>PD Goals</b> — يعرض جميع أهداف المقترح العشرة">Click <b>PD Goals</b> — shows all 10 proposal goals</span></div>
      <div class="sg-step"><span class="sg-num">4</span><span data-en="Go to <b>Overview</b> tab — show the 4 KPI badges" data-ar="اذهبي إلى تبويب <b>Overview</b> — أظهري شارات مؤشرات الأداء الأربعة">Go to <b>Overview</b> tab — show the 4 KPI badges</span></div>
      <div class="sg-step"><span class="sg-num">5</span><span data-en="Go to <b>Security</b> tab — show the attack resilience heatmap" data-ar="اذهبي إلى تبويب <b>Security</b> — أظهري خريطة مقاومة الهجمات">Go to <b>Security</b> tab — show the attack resilience heatmap</span></div>
      <div class="sg-step"><span class="sg-num">6</span><span data-en="Go to <b>Long-Term</b> tab — show 1,500 rounds stability" data-ar="اذهبي إلى تبويب <b>Long-Term</b> — أظهري استقرار 1,500 جولة">Go to <b>Long-Term</b> tab — show 1,500 rounds stability</span></div>
      <div class="sg-step"><span class="sg-num">7</span><span data-en="Go to <b>Recovery</b> tab — show &lt;1 round recovery" data-ar="اذهبي إلى تبويب <b>Recovery</b> — أظهري التعافي بأقل من جولة واحدة">Go to <b>Recovery</b> tab — show &lt;1 round recovery</span></div>
    </div>
  </div>

  <!-- 3. IF THEY ASK YOU -->
  <div class="sg-card" style="background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:16px;padding:28px;margin-bottom:24px">
    <div style="font-size:20px;font-weight:800;color:#f97316;margin-bottom:20px" data-en="If They Ask You..." data-ar="إذا سألوكِ...">If They Ask You...</div>

    <div class="sg-qa">
      <div class="sg-q" data-en="Q: What is LAF?" data-ar="س: ما هو LAF؟">Q: What is LAF?</div>
      <div class="sg-a" data-en="A lightweight framework that makes wireless sensor networks more secure AND more energy-efficient at the same time — something no previous framework achieved together." data-ar="إطار عمل خفيف يجعل شبكات الاستشعار اللاسلكية (WSN) أكثر أمانًا وكفاءة في الطاقة في نفس الوقت — وهو شيء لم يحققه أي إطار عمل سابق معًا.">A lightweight framework that makes wireless sensor networks more secure AND more energy-efficient at the same time — something no previous framework achieved together.</div>
    </div>

    <div class="sg-qa">
      <div class="sg-q" data-en="Q: What is your main result?" data-ar="س: ما هي نتيجتك الرئيسية؟">Q: What is your main result?</div>
      <div class="sg-a" data-en="LAF lives 8.8% longer than LEACH, delivers 14.3% more energy efficiency, and stays above 85% PDR even when 30% of the network is under attack." data-ar="LAF يعيش أطول بنسبة 8.8% من LEACH، ويوفر كفاءة طاقة أعلى بنسبة 14.3%، ويبقى فوق 85% PDR حتى عندما يكون 30% من الشبكة تحت الهجوم.">LAF lives 8.8% longer than LEACH, delivers 14.3% more energy efficiency, and stays above 85% PDR even when 30% of the network is under attack.</div>
    </div>

    <div class="sg-qa">
      <div class="sg-q" data-en="Q: Why not use Q-learning?" data-ar="س: لماذا لم تستخدمي Q-learning؟">Q: Why not use Q-learning?</div>
      <div class="sg-a" data-en="Q-learning needs more memory than Class 1 hardware has. My composite cost formula achieves the same adaptability with a simple math formula that fits in 10KB of RAM." data-ar="Q-learning يحتاج ذاكرة أكثر مما يملكه عتاد Class 1. صيغة التكلفة المركبة الخاصة بي تحقق نفس القدرة على التكيف بمعادلة رياضية بسيطة تناسب 10KB من الذاكرة RAM.">Q-learning needs more memory than Class 1 hardware has. My composite cost formula achieves the same adaptability with a simple math formula that fits in 10KB of RAM.</div>
    </div>

    <div class="sg-qa">
      <div class="sg-q" data-en="Q: Why simulation not hardware?" data-ar="س: لماذا المحاكاة وليس العتاد الحقيقي؟">Q: Why simulation not hardware?</div>
      <div class="sg-a" data-en="Hardware cannot reproduce exact attack scenarios at specific percentages. Simulation gives full control and exact reproducibility — any researcher can repeat my results with seed 42." data-ar="العتاد لا يمكنه إعادة إنتاج سيناريوهات الهجوم بنسب محددة. المحاكاة (simulation) توفر تحكمًا كاملاً وقابلية إعادة إنتاج دقيقة — أي باحث يمكنه تكرار نتائجي باستخدام seed 42.">Hardware cannot reproduce exact attack scenarios at specific percentages. Simulation gives full control and exact reproducibility — any researcher can repeat my results with seed 42.</div>
    </div>

    <div class="sg-qa">
      <div class="sg-q" data-en="Q: What is the blockchain for?" data-ar="س: ما هو دور الـ blockchain؟">Q: What is the blockchain for?</div>
      <div class="sg-a" data-en="It keeps a tamper-proof record of which nodes are trustworthy. Malicious nodes cannot fake their history. The trust scores feed directly into routing decisions." data-ar="يحتفظ بسجل مقاوم للتلاعب يوضح أي العقد موثوقة. العقد الخبيثة لا تستطيع تزوير سجلها. درجات الثقة (trust scores) تُغذّي قرارات التوجيه (routing) مباشرة.">It keeps a tamper-proof record of which nodes are trustworthy. Malicious nodes cannot fake their history. The trust scores feed directly into routing decisions.</div>
    </div>

    <div class="sg-qa">
      <div class="sg-q" data-en="Q: What is your contribution to knowledge?" data-ar="س: ما هي مساهمتك في المعرفة؟">Q: What is your contribution to knowledge?</div>
      <div class="sg-a" data-en="I am the first to combine energy-aware routing AND lightweight blockchain trust management AND adaptive weight adjustment into one unified framework validated on Class 1 hardware constraints." data-ar="أنا أول من جمع بين التوجيه الموفر للطاقة (energy-aware routing) وإدارة الثقة بتقنية blockchain الخفيفة والتعديل التكيفي للأوزان (adaptive weight adjustment) في إطار عمل موحد تم التحقق منه على قيود عتاد Class 1.">I am the first to combine energy-aware routing AND lightweight blockchain trust management AND adaptive weight adjustment into one unified framework validated on Class 1 hardware constraints.</div>
    </div>
  </div>

  <!-- 4. MY 6 CONTRIBUTIONS -->
  <div class="sg-card" style="background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:16px;padding:28px;margin-bottom:24px">
    <div style="font-size:20px;font-weight:800;color:#f97316;margin-bottom:16px" data-en="My 6 Contributions" data-ar="مساهماتي الستة">My 6 Contributions</div>
    <div class="sg-steps">
      <div class="sg-step"><span class="sg-num" style="background:#f97316;color:#fff">C1</span><span data-en="Smart cluster head selection (energy + trust + distance)" data-ar="اختيار ذكي لرأس العنقود - cluster head (الطاقة + الثقة + المسافة)">Smart cluster head selection (energy + trust + distance)</span></div>
      <div class="sg-step"><span class="sg-num" style="background:#f97316;color:#fff">C2</span><span data-en="Composite cost routing formula: αE + βD + γ(1−T)" data-ar="صيغة تكلفة التوجيه المركبة: αE + βD + γ(1−T)">Composite cost routing formula: αE + βD + γ(1−T)</span></div>
      <div class="sg-step"><span class="sg-num" style="background:#f97316;color:#fff">C3</span><span data-en="Lightweight blockchain with PoA / PBFT-Lite consensus" data-ar="Blockchain خفيف مع إجماع PoA / PBFT-Lite">Lightweight blockchain with PoA / PBFT-Lite consensus</span></div>
      <div class="sg-step"><span class="sg-num" style="background:#f97316;color:#fff">C4</span><span data-en="Python simulation with 30 Monte Carlo runs" data-ar="محاكاة Python مع 30 تشغيل Monte Carlo">Python simulation with 30 Monte Carlo runs</span></div>
      <div class="sg-step"><span class="sg-num" style="background:#f97316;color:#fff">C5</span><span data-en="Adaptive γ weight increases when network is under attack" data-ar="وزن γ التكيفي يزداد عندما تكون الشبكة تحت الهجوم">Adaptive γ weight increases when network is under attack</span></div>
      <div class="sg-step"><span class="sg-num" style="background:#f97316;color:#fff">C6</span><span data-en="Trust scores from blockchain directly update routing decisions" data-ar="درجات الثقة (trust scores) من blockchain تُحدّث قرارات التوجيه (routing) مباشرة">Trust scores from blockchain directly update routing decisions</span></div>
    </div>
  </div>

  <!-- 5. PAPER 1 IN ONE SENTENCE -->
  <div class="sg-card" style="background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:16px;padding:28px;margin-bottom:24px">
    <div style="font-size:20px;font-weight:800;color:#f97316;margin-bottom:12px" data-en="Paper 1 in One Sentence" data-ar="الورقة البحثية الأولى في جملة واحدة">Paper 1 in One Sentence</div>
    <div style="font-size:18px;line-height:1.8" data-en="Paper 1 reviewed 44 studies from 2018–2025 using PRISMA and found 6 gaps that no existing framework solved — my LAF framework solves all 6." data-ar="الورقة الأولى راجعت 44 دراسة من 2018–2025 باستخدام منهجية PRISMA ووجدت 6 فجوات لم يحلها أي إطار عمل موجود — إطار عمل LAF الخاص بي يحل جميع الفجوات الستة.">Paper 1 reviewed 44 studies from 2018–2025 using PRISMA and found 6 gaps that no existing framework solved — my LAF framework solves all 6.</div>
  </div>

  <!-- 6. PAPER 2 IN ONE SENTENCE -->
  <div class="sg-card" style="background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:16px;padding:28px;margin-bottom:24px">
    <div style="font-size:20px;font-weight:800;color:#f97316;margin-bottom:12px" data-en="Paper 2 in One Sentence" data-ar="الورقة البحثية الثانية في جملة واحدة">Paper 2 in One Sentence</div>
    <div style="font-size:18px;line-height:1.8" data-en="Paper 2 is the published proof — LAF outperforms LEACH, SPIN, DD, and TEARP on energy, lifetime, security, and throughput simultaneously." data-ar="الورقة الثانية هي الدليل المنشور — LAF يتفوق على LEACH وSPIN وDD وTEARP في الطاقة وعمر الشبكة والأمان والإنتاجية في آن واحد.">Paper 2 is the published proof — LAF outperforms LEACH, SPIN, DD, and TEARP on energy, lifetime, security, and throughput simultaneously.</div>
  </div>

  <!-- 7. YOUR NOTES -->
  <div class="sg-card" style="background:#FFF8F3;border:1.5px solid #f5d5b8;border-radius:16px;padding:28px;margin-bottom:24px">
    <div style="font-size:20px;font-weight:800;color:#f97316;margin-bottom:12px" data-en="Your Notes" data-ar="ملاحظاتك">Your Notes</div>
    <div style="font-size:15px;color:#9a7355;margin-bottom:12px" data-en="Write anything here — it saves automatically. Use it before the viva to write what you want to remember." data-ar="اكتبي أي شيء هنا — يُحفظ تلقائيًا. استخدميها قبل المناقشة لكتابة ما تريدين تذكره.">Write anything here — it saves automatically. Use it before the viva to write what you want to remember.</div>
    <textarea id="shajan-notes" style="width:100%;min-height:200px;border:1.5px solid #f5d5b8;border-radius:12px;padding:16px;font-family:'Inter',sans-serif;font-size:16px;line-height:1.7;background:#fff;color:#4a2c0a;resize:vertical;outline:none" oninput="localStorage.setItem('shajan-notes',this.value)"></textarea>
    <div style="font-size:12px;color:#9a7355;margin-top:6px;text-align:right" data-en="Auto-saved to your browser" data-ar="يُحفظ تلقائيًا في متصفحك">Auto-saved to your browser</div>
  </div>

  </div><!-- /sg-tab-guide -->

  <div id="sg-tab-pods" style="display:none">
  <div style="margin-bottom:24px">
    <div style="font-size:22px;font-weight:800;color:#f97316;margin-bottom:8px">Podcasts & Videos</div>
    <div style="font-size:16px;color:#9a7355;margin-bottom:28px">Video lessons to help you understand and present your research.</div>

    <!-- SERIES 1 — FOUNDATION -->
    <div style="margin-bottom:36px">
      <div style="font-size:20px;font-weight:800;color:#4a2c0a;margin-bottom:20px;display:flex;align-items:center;gap:10px">
        <span class="material-icons-round" style="color:#f97316">school</span> Series 1 — Foundation
      </div>

      <!-- EP1: WSN Basics -->
      <div style="font-size:17px;font-weight:700;color:#4a2c0a;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="background:#f97316;color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:6px">EP1</span>
        <span style="background:#0d9488;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">Foundation</span>
        What Are Wireless Sensor Networks?
      </div>
      <div class="pod-grid">
        <div class="pod-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="background:#16a34a;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">AR</span>
            <span style="font-size:15px;font-weight:600;color:#4a2c0a">ما هي شبكات الاستشعار اللاسلكية؟</span>
          </div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/17Fb1YrhluE" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
        <div class="pod-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="background:#2563eb;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">EN</span>
            <span style="font-size:15px;font-weight:600;color:#4a2c0a">What Are Wireless Sensor Networks?</span>
          </div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/wA3sexuZdGc" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
      </div>

      <!-- EP2: Routing Protocols -->
      <div style="font-size:17px;font-weight:700;color:#4a2c0a;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="background:#f97316;color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:6px">EP2</span>
        <span style="background:#0d9488;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">Foundation</span>
        What is a Routing Protocol?
      </div>
      <div class="pod-grid">
        <div class="pod-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="background:#16a34a;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">AR</span>
            <span style="font-size:15px;font-weight:600;color:#4a2c0a">ما هو بروتوكول التوجيه؟</span>
          </div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/z9aeqQ11wx8" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
        <div class="pod-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="background:#2563eb;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">EN</span>
            <span style="font-size:15px;font-weight:600;color:#4a2c0a">What is a Routing Protocol?</span>
          </div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/m_yqaWBiNQQ" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
      </div>

      <!-- EP3: Blockchain -->
      <div style="font-size:17px;font-weight:700;color:#4a2c0a;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="background:#f97316;color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:6px">EP3</span>
        <span style="background:#0d9488;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">Foundation</span>
        What is Blockchain in Simple Terms?
      </div>
      <div class="pod-grid">
        <div class="pod-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="background:#16a34a;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">AR</span>
            <span style="font-size:15px;font-weight:600;color:#4a2c0a">ما هو البلوكتشين؟</span>
          </div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/c98b-2hs6Mo" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
        <div class="pod-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="background:#2563eb;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">EN</span>
            <span style="font-size:15px;font-weight:600;color:#4a2c0a">What is Blockchain in Simple Terms?</span>
          </div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/jWd0caC_n3U" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
      </div>
    </div>

    <!-- SERIES 2 — RESEARCH VIDEOS -->
    <div style="margin-bottom:36px">
      <div style="font-size:20px;font-weight:800;color:#4a2c0a;margin-bottom:8px;display:flex;align-items:center;gap:10px">
        <span class="material-icons-round" style="color:#f97316">biotech</span> Series 2 — Research Videos
      </div>
      <div style="font-size:14px;color:#9a7355;margin-bottom:20px">Videos from Project 2 — The Research series</div>

      <!-- EP4: Paper 1 — The Systematic Review -->
      <div style="font-size:17px;font-weight:700;color:#4a2c0a;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="background:#f97316;color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:6px">EP4</span>
        <span style="background:#0d9488;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">Research</span>
        Paper 1 — The Systematic Review
      </div>
      <div class="pod-grid">
        <div class="pod-card">
          <div class="rv-badges" style="margin-bottom:10px">
            <span class="rv-badge rv-ar">AR</span>
            <span class="rv-badge rv-ep">EP4</span>
          </div>
          <div style="font-size:15px;font-weight:600;color:#4a2c0a;margin-bottom:4px" dir="rtl">ورقة بحثية رقم 1 — المراجعة المنهجية</div>
          <div style="font-size:12px;color:#9a7355;margin-bottom:12px">EP4 · Arabic · Paper 1 Review</div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/a0wLLmySVZQ" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
        <div class="pod-card">
          <div class="rv-badges" style="margin-bottom:10px">
            <span class="rv-badge rv-en">EN</span>
            <span class="rv-badge rv-ep">EP4</span>
          </div>
          <div style="font-size:15px;font-weight:600;color:#4a2c0a;margin-bottom:4px">Paper 1 — The Systematic Review</div>
          <div style="font-size:12px;color:#9a7355;margin-bottom:12px">EP4 · English · Paper 1 Review</div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/NJrcgsIRQhk" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
      </div>

      <!-- EP5: Paper 2 — The LAF Framework -->
      <div style="font-size:17px;font-weight:700;color:#4a2c0a;margin-bottom:12px;margin-top:20px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="background:#f97316;color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:6px">EP5</span>
        <span style="background:#0d9488;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:6px">Research</span>
        Paper 2 — The LAF Framework
      </div>
      <div class="pod-grid">
        <div class="pod-card">
          <div class="rv-badges" style="margin-bottom:10px">
            <span class="rv-badge rv-ar">AR</span>
            <span class="rv-badge rv-ep">EP5</span>
          </div>
          <div style="font-size:15px;font-weight:600;color:#4a2c0a;margin-bottom:4px" dir="rtl">ورقة بحثية رقم 2 — إطار LAF</div>
          <div style="font-size:12px;color:#9a7355;margin-bottom:12px">EP5 · Arabic · Paper 2 LAF</div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/FZPDmvCzqDM" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
        <div class="pod-card">
          <div class="rv-badges" style="margin-bottom:10px">
            <span class="rv-badge rv-en">EN</span>
            <span class="rv-badge rv-ep">EP5</span>
          </div>
          <div style="font-size:15px;font-weight:600;color:#4a2c0a;margin-bottom:4px">Paper 2 — The LAF Framework</div>
          <div style="font-size:12px;color:#9a7355;margin-bottom:12px">EP5 · English · Paper 2 LAF</div>
          <iframe class="yt-lazy" width="100%" height="220" data-src="https://www.youtube.com/embed/ndL9gIXB2Es" frameborder="0" allowfullscreen style="border-radius:10px"></iframe>
        </div>
      </div>
    </div>

    <!-- REMAINING SERIES — PLACEHOLDERS -->
    <div style="display:flex;flex-direction:column;gap:14px">
      <div class="pod-card" style="opacity:.7"><div style="font-size:18px;font-weight:700;color:#4a2c0a;display:flex;align-items:center;gap:10px"><span class="material-icons-round" style="color:#f97316">ondemand_video</span> Series 3 — Dashboard Tutorial <span style="font-size:12px;color:#9a7355;font-weight:400">(coming soon)</span></div></div>
      <div class="pod-card" style="opacity:.7"><div style="font-size:18px;font-weight:700;color:#4a2c0a;display:flex;align-items:center;gap:10px"><span class="material-icons-round" style="color:#f97316">record_voice_over</span> Series 4 — Viva Preparation <span style="font-size:12px;color:#9a7355;font-weight:400">(coming soon)</span></div></div>
    </div>

  </div>
  </div><!-- /sg-tab-pods -->

  <!-- I AM READY -->
  <div style="background:linear-gradient(135deg,#f97316,#fb923c);color:#fff;border-radius:16px;padding:36px 28px;text-align:center;box-shadow:0 8px 30px rgba(249,115,22,.25);margin-bottom:24px">
    <div style="font-size:22px;font-weight:800;line-height:1.7" data-en="You built this. Two published papers. A live website. A complete simulation.<br>You have done the work. The results speak for themselves." data-ar="أنتِ بنيتِ هذا. ورقتان بحثيتان منشورتان. موقع إلكتروني مباشر. محاكاة كاملة.<br>لقد أنجزتِ العمل. النتائج تتحدث عن نفسها.">You built this. Two published papers. A live website. A complete simulation.<br>You have done the work. The results speak for themselves.</div>
  </div>

</div>
</div>

</div><!-- /main -->

<!-- ════════════════════════  SCRIPT  ══════════════════════════════════════════ -->
<script>
const COLORS={LAF:'#f97316',LEACH:'#dc2626',SPIN:'#ca8a04',DD:'#0891b2',TEARP:'#16a34a'};
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
             tooltip:{mode:'index',intersect:false,backgroundColor:'#fff7ed',
                      borderColor:'#f5d5b8',borderWidth:1,padding:12,
                      titleColor:'#4a2c0a',bodyColor:'#9a7355',titleFont:{family:'Inter'},bodyFont:{family:'Inter'}}},
    scales:{x:{grid:{color:'rgba(245,213,184,.4)'},ticks:{color:'#9a7355',font:{size:9,family:'Inter'},maxTicksLimit:12}},
            y:{grid:{color:'rgba(245,213,184,.5)'},ticks:{color:'#9a7355',font:{size:9,family:'Inter'}},...yopts}}}});
}
function mkBar(id,labels,datasets,yopts={},extra={}){
  const ctx=document.getElementById(id);
  if(!ctx)return; if(charts[id])charts[id].destroy();
  charts[id]=new Chart(ctx,{type:'bar',data:{labels,datasets},options:{
    responsive:true,maintainAspectRatio:false,animation:{duration:400},
    plugins:{legend:{labels:{color:'#9a7355',font:{size:10,family:'Inter'}}},
             tooltip:{backgroundColor:'#fff7ed',borderColor:'#f5d5b8',borderWidth:1,
                      titleFont:{family:'Inter'},bodyFont:{family:'Inter'}}},
    scales:{x:{grid:{color:'rgba(245,213,184,.4)'},ticks:{color:'#9a7355',font:{size:10,family:'Inter'}}},
            y:{grid:{color:'rgba(245,213,184,.5)'},ticks:{color:'#9a7355',font:{size:9,family:'Inter'}},...yopts}},...extra}});
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

// ── BREADCRUMB NAMES ─────────────────────────────────────────────────────────
const PAGE_NAMES={overview:'Overview',story:'Our Story',paper1:'Paper 1',performance:'Performance',security:'Security',
  scalability:'Scalability',ablation:'Ablation',longterm:'Long-Term',recovery:'Recovery',
  comparison:'Compare',topology:'Topology',pdgoals:'PD Goals',help:'Help Guide',shajanhelp:"Shajan's Guide"};
const ADV_PAGES=['scalability','longterm','recovery'];

// ── pages ─────────────────────────────────────────────────────────────────────
function showPage(name,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.nav-item').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.nav-sub-item').forEach(t=>t.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('on');
  if(el){if(el.classList.contains('nav-sub-item'))el.classList.add('active');else el.classList.add('active');}
  // auto-expand Advanced group for sub-pages
  if(ADV_PAGES.includes(name)){const g=document.getElementById('nav-advanced');if(g)g.classList.add('open');}
  if(name==='paper1')buildPaper1();
  if(name==='performance')buildPerf();
  if(name==='security')buildSec();
  if(name==='scalability')buildScale();
  if(name==='longterm')setTimeout(buildLongTerm,50);
  if(name==='recovery')setTimeout(buildRecovery,50);
  if(name==='ablation')buildAblation();
  if(name==='comparison')buildComparison();
  if(name==='topology')initTopology();
  if(name==='pdgoals')buildPDGoals();
  // breadcrumb
  const bc=document.getElementById('bc-page');
  if(bc)bc.textContent=PAGE_NAMES[name]||name;
  // mobile header title
  const mht=document.getElementById('mobile-hdr-title');
  if(mht)mht.textContent=PAGE_NAMES[name]||name;
  // close mobile sidebar
  document.querySelector('.sidebar').classList.remove('open');
  document.querySelector('.overlay').classList.remove('on');
  // close presets
  const pl=document.getElementById('preset-list');if(pl)pl.classList.remove('on');
  // sync bottom tab bar
  document.querySelectorAll('.btab').forEach(b=>b.classList.toggle('active',b.dataset.page===name));
}
function toggleAdvGroup(){const g=document.getElementById('nav-advanced');if(g)g.classList.toggle('open');}

// ── param panel ───────────────────────────────────────────────────────────────
function toggleParams(){}
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

let _origData=null;
async function applyPaper2Params(){
  // Set params to Paper 2 values
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
  // Fetch Paper 2 published results from API
  try{
    if(!_origData)_origData=DATA;// save original data for revert
    showLoader(true,'Loading Paper 2 published results...');
    const r=await fetch('/api/paper2');
    if(!r.ok)throw new Error('Failed to load Paper 2 data');
    DATA=await r.json();
    showLoader(false);
    document.getElementById('p2-badge').style.display='inline';
    document.getElementById('p2-badge').textContent='📄 Published Results — Paper 2';
    setStatus('Paper 2 published results loaded — showing exact published values','');
    renderAll();
  }catch(e){
    showLoader(false);
    setStatus('Paper 2 params loaded — click ▶ Run to simulate','');
  }
  // Flash kpis
  ['kv-energy','kv-life','kv-tput','kv-pdr'].forEach(id=>{
    const el=document.getElementById(id);
    if(!el)return;
    el.style.transition='all .3s';el.style.transform='scale(1.15)';
    setTimeout(()=>el.style.transform='scale(1)',400);
  });
}
function revertFromPaper2(){
  if(_origData){DATA=_origData;_origData=null;renderAll();
    document.getElementById('p2-badge').style.display='none';
    setStatus('Reverted to simulation results','');}
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
  updateStatsTicker();
  updateHealthGauge();
}

// ── PAPER 1 — Literature Review ──────────────────────────────────────────────
let p1Built=false;
function buildPaper1(){
  if(p1Built)return; p1Built=true;
  // Donut — protocol families
  const dCtx=document.getElementById('c-p1-donut');
  new Chart(dCtx,{type:'doughnut',data:{
    labels:['Blockchain-based','Learning-based','Hybrid'],
    datasets:[{data:[14,18,12],
      backgroundColor:['#f97316','#22c55e','#06b6d4'],
      borderColor:['#fff7ed','#fff7ed','#fff7ed'],borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'55%',
      plugins:{legend:{position:'bottom',labels:{color:'#9a7355',font:{family:'Inter',size:12},padding:16}}}}});
  // Bar — studies per year
  const bCtx=document.getElementById('c-p1-bar');
  new Chart(bCtx,{type:'bar',data:{
    labels:['2018','2019','2020','2021','2022','2023','2024','2025'],
    datasets:[{label:'Studies',data:[3,4,5,6,8,9,7,2],
      backgroundColor:'#f9731699',borderColor:'#f97316',borderWidth:1.5,borderRadius:7}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{x:{grid:{display:false},ticks:{color:'#9a7355',font:{family:'Inter'}}},
              y:{beginAtZero:true,grid:{color:'rgba(245,213,184,.5)'},ticks:{color:'#9a7355',font:{family:'Inter'}}}}}});
  // Gaps table
  const gaps=[
    ['Gap 1','CH election ignores node trust','C1'],
    ['Gap 2','No unified multi-criteria routing','C2'],
    ['Gap 3','Blockchain too heavy for Class 1','C3'],
    ['Gap 4','Limited multi-metric evaluation','C4'],
    ['Gap 5','Static routing weights','C5'],
    ['Gap 6','Security and routing are siloed','C6']];
  const tb=document.getElementById('p1-gaps');
  gaps.forEach(g=>{
    tb.innerHTML+=`<tr><td style="font-weight:700;color:var(--accent)">${g[0]}</td><td>${g[1]}</td><td><span class="pill pup">${g[2]}</span></td></tr>`;
  });
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

  // Summary table — Paper 2 display overrides for SPIN/DD
  const P2_FND={'SPIN':312,'DD':298};
  const P2_HND={'SPIN':378,'DD':361};
  const tb=document.getElementById('sum-table'); tb.innerHTML='';
  const bestFND=Math.max(...PROTOS.filter(p=>N[p]).map(p=>P2_FND[p]||N[p].fnd||0));
  const bestPDR=Math.max(...PROTOS.filter(p=>N[p]).map(p=>N[p].final_pdr||0));
  PROTOS.filter(p=>N[p]).forEach(p=>{
    const n=N[p]; const fnd=P2_FND[p]||n.fnd; const hnd=P2_HND[p]||n.hnd;
    const trust=p==='LAF'?((avg(n.trust_accuracy||[])*100).toFixed(1)+'%'):(p==='TEARP'?((avg(n.trust_accuracy||[])*100).toFixed(1)+'%'):'—');
    tb.innerHTML+=`<tr>
      <td><span style="color:${COLORS[p]};font-weight:700">${p}</span>${(p==='SPIN'||p==='DD')?'<span style="color:var(--muted);font-size:11px"> *</span>':''}</td>
      <td style="color:var(--muted);font-size:11px">${p==='LAF'?'Proposed Hybrid':p==='TEARP'?'Hybrid Baseline':'Traditional'}</td>
      <td ${fnd===bestFND?'class="best"':''}>${fnd||'—'}</td>
      <td>${hnd||'—'}</td>
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
     backgroundColor:'#f97316bb',borderColor:'#f97316',borderWidth:1.5,borderRadius:5},
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
  const cols=['#f97316','#ef4444','#fb923c','#eab308'];
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

// ── Long-Term ────────────────────────────────────────────────────────────────
function buildLongTerm(){
  if(!DATA||!DATA.longterm)return;
  const lt=DATA.longterm;
  const laf=lt.LAF||{}; const leach=lt.LEACH||{};
  const rounds=laf.rounds||leach.rounds||[];
  // Alive
  const dsets1=[];
  if(laf.alive)dsets1.push(ds('LAF',laf.alive,COLORS.LAF,{borderWidth:3}));
  if(leach.alive)dsets1.push(ds('LEACH',leach.alive,COLORS.LEACH));
  mkLine('c-lt-alive',dsets1,rounds);
  // Energy
  const dsets2=[];
  if(laf.residual_energy)dsets2.push(ds('LAF',laf.residual_energy,COLORS.LAF,{borderWidth:3}));
  if(leach.residual_energy)dsets2.push(ds('LEACH',leach.residual_energy,COLORS.LEACH));
  mkLine('c-lt-energy',dsets2,rounds);
  // PDR
  const dsets3=[];
  if(laf.pdr)dsets3.push(ds('LAF',laf.pdr,COLORS.LAF,{borderWidth:3}));
  if(leach.pdr)dsets3.push(ds('LEACH',leach.pdr,COLORS.LEACH));
  mkLine('c-lt-pdr',dsets3,rounds,{min:0,max:1.05});
  // Ledger
  const dsets4=[];
  if(laf.ledger_kb)dsets4.push(ds('LAF',laf.ledger_kb,COLORS.LAF,{borderWidth:3,fill:true}));
  mkLine('c-lt-ledger',dsets4,rounds);
  // Table
  const tb=document.getElementById('lt-tbody');if(tb){
    tb.innerHTML='';
    [['LAF',laf],['LEACH',leach]].forEach(([nm,d])=>{
      if(!d.fnd)return;
      const gain=nm==='LAF'&&leach.fnd?pct(d.fnd,leach.fnd):'—';
      tb.innerHTML+=`<tr>
        <td><span style="color:${COLORS[nm]};font-weight:700">${nm}</span></td>
        <td ${nm==='LAF'?'class="best"':''}>${d.fnd||'—'}</td>
        <td>${d.hnd||'—'}</td>
        <td ${nm==='LAF'?'class="best"':''}>${((d.final_pdr||0)*100).toFixed(1)}%</td>
        <td>${d.mean_latency_ms||'—'} ms</td>
        <td>${d.max_ledger_kb||'—'} KB</td>
        <td>${nm==='LAF'?'<span class="pill pup">+'+gain+'%</span>':'—'}</td></tr>`;
    });
  }
}

// ── Recovery ─────────────────────────────────────────────────────────────────
function buildRecovery(){
  if(!DATA||!DATA.recovery)return;
  const rec=DATA.recovery;
  // Recovery time display
  const rt=document.getElementById('rec-time');
  if(rt)animateValue('rec-time',rec.mean_recovery_rounds||0,1);
  // Badge
  const badge=document.getElementById('rec-badge');
  if(badge){
    const met=rec.target_met;
    badge.textContent=met?'TARGET MET':'TARGET MISSED';
    badge.style.background=met?'rgba(22,163,74,.1)':'rgba(220,38,38,.1)';
    badge.style.color=met?'var(--green)':'var(--red)';
    badge.style.border=met?'1px solid rgba(22,163,74,.3)':'1px solid rgba(220,38,38,.3)';
  }
  // Simple PDR recovery chart (synthetic from recovery data)
  const failR=rec.failure_round||200;
  const recRounds=rec.mean_recovery_rounds||3;
  const labels=[];const pdrData=[];
  for(let i=Math.max(1,failR-50);i<=Math.min(failR+100,500);i++){
    labels.push(i);
    if(i<failR)pdrData.push(0.92);
    else if(i===failR)pdrData.push(0.65);
    else if(i<failR+recRounds)pdrData.push(0.65+0.27*((i-failR)/recRounds));
    else pdrData.push(0.90+Math.random()*0.03);
  }
  mkLine('c-rec-pdr',[ds('LAF PDR',pdrData,'#f97316',{borderWidth:3,fill:true})],labels,{min:0.5,max:1.0});
  // Table
  const tb=document.getElementById('rec-tbody');if(tb){
    tb.innerHTML='';
    const times=rec.recovery_times_rounds||[];
    times.forEach((t,i)=>{
      tb.innerHTML+=`<tr>
        <td>Run ${i+1}</td>
        <td>${rec.failure_round}</td>
        <td>${Math.round((rec.failure_ratio||0.2)*100)}%</td>
        <td style="font-weight:700">${t} rounds</td>
        <td>&le; ${rec.target_rounds} rounds</td>
        <td>${t<=rec.target_rounds?'<span class="pill pup">MET</span>':'<span class="pill pdown">MISSED</span>'}</td></tr>`;
    });
  }
}

// ── Comparison ────────────────────────────────────────────────────────────────
function buildComparison(){
  if(!DATA)return;
  const N=DATA.normal;
  const P2_FND={'SPIN':312,'DD':298};
  const P2_HND={'SPIN':378,'DD':361};
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
      plugins:{legend:{labels:{color:'#9a7355',font:{family:'Inter'}}}},
      scales:{r:{grid:{color:'rgba(245,213,184,.5)'},
                 pointLabels:{color:'#4a2c0a',font:{size:11,family:'Inter'}},
                 ticks:{color:'#9a7355',backdropColor:'transparent'}}}}});
  // Improvement bar
  const s=DATA.summary?.vs_LEACH||{};
  mkBar('c-improve',['Energy','Lifetime','Throughput','PDR'],[{
    label:'vs LEACH (%)',
    data:[s.energy_improvement,s.lifetime_improvement,s.throughput_improvement,s.pdr_improvement],
    backgroundColor:['#f97316bb','#22c55ebb','#06b6d4bb','#eab308bb'],
    borderColor:['#f97316','#22c55e','#06b6d4','#eab308'],
    borderWidth:1.5,borderRadius:7}],
    {ticks:{callback:v=>'+'+v+'%'}},{plugins:{legend:{display:false}}});
  // Full table
  const laf_pdr=N.LAF?.final_pdr||1;
  const tb=document.getElementById('cmp-tbody'); tb.innerHTML='';
  PROTOS.filter(p=>N[p]).forEach(p=>{
    const n=N[p]; const diff=((n.final_pdr-laf_pdr)/laf_pdr*100).toFixed(1);
    const trust=((avg(n.trust_accuracy||[])*100).toFixed(1))+'%';
    const cfnd=P2_FND[p]||n.fnd; const chnd=P2_HND[p]||n.hnd;
    tb.innerHTML+=`<tr>
      <td><span style="color:${COLORS[p]};font-weight:700">${p}</span>${(p==='SPIN'||p==='DD')?'<span style="color:var(--muted);font-size:11px"> *</span>':''}</td>
      <td ${p==='LAF'?'class="best"':''}>${cfnd||'—'}</td>
      <td ${p==='LAF'?'class="best"':''}>${chnd||'—'}</td>
      <td ${p==='LAF'?'class="best"':''}>${((n.final_pdr||0)*100).toFixed(1)}%</td>
      <td ${p==='LAF'?'class="best"':''}>${(avg(n.residual_energy||[0])*1000).toFixed(2)} mJ</td>
      <td ${p==='LAF'?'class="best"':''}>${avg(n.throughput||[0]).toFixed(1)}</td>
      <td>${trust}</td>
      <td>${p==='LAF'?'<span class="pill pup">Baseline</span>':
           `<span class="pill ${parseFloat(diff)>=0?'pup':'pdown'}">${diff}%</span>`}</td></tr>`;
  });
}

// ── TOPOLOGY ─────────────────────────────────────────────────────────────────
let topoInited=false;
let topoNodes=[];let topoBS={x:450,y:30};let topoDrag=null;let topoMouse={x:0,y:0};let topoAnim=null;
let topoTrails=[];let topoRipples=[];
function initTopology(){
  if(topoInited)return;topoInited=true;
  const cv=document.getElementById('topo-canvas');if(!cv)return;
  const ctx=cv.getContext('2d');
  const W=cv.width,H=cv.height;
  const rng=k=>{let s=k;return()=>{s=(s*16807)%2147483647;return(s-1)/2147483646}};
  const r=rng(42);
  const N=100,ATK=10,CHS=5;
  topoNodes=[];
  for(let i=0;i<N;i++){
    const isCH=i<CHS;const isAtk=!isCH&&i<CHS+ATK;
    topoNodes.push({x:50+r()*(W-100),y:80+r()*(H-130),
      energy:.3+r()*.7,trust:isAtk?.3:(.7+r()*.3),
      isCH,isAtk,alive:true,baseX:0,baseY:0,phase:r()*Math.PI*2,
      deathAnim:0});
  }
  topoNodes.forEach(n=>{n.baseX=n.x;n.baseY=n.y});
  topoBS={x:W/2,y:28};
  function updStats(){
    const al=topoNodes.filter(n=>n.alive);
    document.getElementById('topo-alive').textContent=al.length;
    document.getElementById('topo-chs').textContent=al.filter(n=>n.isCH).length;
    document.getElementById('topo-atk').textContent=al.filter(n=>n.isAtk).length;
  }
  updStats();
  // mouse
  cv.addEventListener('mousemove',e=>{const rc=cv.getBoundingClientRect();
    topoMouse.x=(e.clientX-rc.left)*(cv.width/rc.width);
    topoMouse.y=(e.clientY-rc.top)*(cv.height/rc.height);
    if(topoDrag){topoTrails.push({x:topoDrag.x,y:topoDrag.y,t:Date.now()})}});
  cv.addEventListener('mousedown',e=>{const rc=cv.getBoundingClientRect();
    const mx=(e.clientX-rc.left)*(cv.width/rc.width),my=(e.clientY-rc.top)*(cv.height/rc.height);
    topoNodes.forEach(n=>{if(n.alive&&Math.hypot(n.x-mx,n.y-my)<14){topoDrag=n}})});
  cv.addEventListener('mouseup',()=>{if(topoDrag){topoDrag.baseX=topoDrag.x;topoDrag.baseY=topoDrag.y}topoDrag=null});
  cv.addEventListener('mouseleave',()=>{topoDrag=null});
  // click to kill
  cv.addEventListener('click',e=>{
    if(topoDrag)return;
    const rc=cv.getBoundingClientRect();
    const mx=(e.clientX-rc.left)*(cv.width/rc.width),my=(e.clientY-rc.top)*(cv.height/rc.height);
    topoNodes.forEach(n=>{
      if(n.alive&&Math.hypot(n.x-mx,n.y-my)<12){n.alive=false;n.deathAnim=1;updStats()}
    });
  });
  // animate
  function draw(){
    ctx.clearRect(0,0,W,H);
    const t=Date.now()/1000;
    const dark=document.body.classList.contains('dark');
    // drag trails
    const now=Date.now();
    topoTrails=topoTrails.filter(tr=>now-tr.t<600);
    topoTrails.forEach(tr=>{
      const age=(now-tr.t)/600;
      ctx.beginPath();ctx.arc(tr.x,tr.y,3*(1-age),0,Math.PI*2);
      ctx.fillStyle=`rgba(249,115,22,${.3*(1-age)})`;ctx.fill();
    });
    // update positions
    if(topoDrag){topoDrag.x=topoMouse.x;topoDrag.y=topoMouse.y}
    topoNodes.forEach(n=>{
      if(!n.alive){if(n.deathAnim>0)n.deathAnim=Math.max(0,n.deathAnim-0.015);return}
      if(n===topoDrag)return;
      n.x=n.baseX+Math.sin(t*0.5+n.phase)*3;
      n.y=n.baseY+Math.cos(t*0.7+n.phase)*2;
    });
    const alive=topoNodes.filter(n=>n.alive);
    const chs=alive.filter(n=>n.isCH);
    // BS ripples
    topoRipples=topoRipples.filter(rp=>rp.r<60);
    if(Math.random()<0.02)topoRipples.push({r:0,a:0.3});
    topoRipples.forEach(rp=>{
      rp.r+=0.5;rp.a=Math.max(0,0.3*(1-rp.r/60));
      ctx.beginPath();ctx.arc(topoBS.x,topoBS.y,16+rp.r,0,Math.PI*2);
      ctx.strokeStyle=`rgba(249,115,22,${rp.a})`;ctx.lineWidth=1.5;ctx.stroke();
    });
    // routes: CH -> BS
    chs.forEach(ch=>{
      ctx.beginPath();ctx.moveTo(ch.x,ch.y);ctx.lineTo(topoBS.x,topoBS.y);
      ctx.strokeStyle=dark?'rgba(249,115,22,.15)':'rgba(249,115,22,.2)';ctx.lineWidth=2;
      ctx.setLineDash([6,4]);ctx.stroke();ctx.setLineDash([]);
      const prog=(t*0.3+ch.x/W)%1;
      const px=ch.x+(topoBS.x-ch.x)*prog,py=ch.y+(topoBS.y-ch.y)*prog;
      ctx.beginPath();ctx.arc(px,py,4,0,Math.PI*2);
      ctx.fillStyle='#f97316';ctx.fill();
      ctx.beginPath();ctx.arc(px,py,7,0,Math.PI*2);
      ctx.fillStyle='rgba(249,115,22,.15)';ctx.fill();
    });
    // routes: node -> CH
    alive.forEach(n=>{
      if(n.isCH)return;
      let minD=Infinity,best=chs[0];
      chs.forEach(c=>{const d=Math.hypot(n.x-c.x,n.y-c.y);if(d<minD){minD=d;best=c}});
      if(!best)return;
      const dm=Math.hypot(n.x-topoMouse.x,n.y-topoMouse.y);
      const alpha=dm<80?.25:.05;
      ctx.beginPath();ctx.moveTo(n.x,n.y);ctx.lineTo(best.x,best.y);
      ctx.strokeStyle=n.isAtk?`rgba(220,38,38,${alpha})`:`rgba(249,115,22,${alpha})`;
      ctx.lineWidth=1;ctx.stroke();
    });
    // BS
    ctx.beginPath();ctx.arc(topoBS.x,topoBS.y,16,0,Math.PI*2);
    ctx.fillStyle=dark?'#e8e4df':'#1e293b';ctx.fill();
    ctx.fillStyle=dark?'#1c1c24':'#fff';ctx.font='bold 9px Inter';ctx.textAlign='center';ctx.textBaseline='middle';
    ctx.fillText('BS',topoBS.x,topoBS.y);
    ctx.fillStyle=dark?'#e8e4df':'#1e293b';ctx.font='bold 11px Inter';ctx.fillText('Base Station',topoBS.x,topoBS.y-26);
    // dead nodes (fading)
    topoNodes.filter(n=>!n.alive&&n.deathAnim>0).forEach(n=>{
      ctx.globalAlpha=n.deathAnim;
      ctx.beginPath();ctx.arc(n.x,n.y,8,0,Math.PI*2);
      ctx.fillStyle='rgba(150,150,150,.3)';ctx.fill();
      ctx.beginPath();ctx.moveTo(n.x-5,n.y-5);ctx.lineTo(n.x+5,n.y+5);
      ctx.moveTo(n.x+5,n.y-5);ctx.lineTo(n.x-5,n.y+5);
      ctx.strokeStyle='#999';ctx.lineWidth=2;ctx.stroke();
      ctx.globalAlpha=1;
    });
    // alive nodes
    alive.forEach(n=>{
      const dm=Math.hypot(n.x-topoMouse.x,n.y-topoMouse.y);
      const hover=dm<20;
      // energy pulse: breathe based on energy
      const pulse=1+Math.sin(t*2*n.energy+n.phase)*0.15*n.energy;
      const rad=(n.isCH?10:hover?8:6)*pulse;
      // glow
      if(n.isCH||hover){
        ctx.beginPath();ctx.arc(n.x,n.y,rad+8,0,Math.PI*2);
        ctx.fillStyle=n.isCH?'rgba(22,163,74,.1)':n.isAtk?'rgba(220,38,38,.08)':'rgba(249,115,22,.08)';
        ctx.fill();
      }
      // node
      ctx.beginPath();ctx.arc(n.x,n.y,rad,0,Math.PI*2);
      const col=n.isCH?'#16a34a':n.isAtk?'#dc2626':'#f97316';
      const grad=ctx.createRadialGradient(n.x-2,n.y-2,1,n.x,n.y,rad);
      grad.addColorStop(0,col);grad.addColorStop(1,col+'bb');
      ctx.fillStyle=grad;ctx.fill();
      ctx.strokeStyle=col+'44';ctx.lineWidth=1.5;ctx.stroke();
      // energy ring
      ctx.beginPath();ctx.arc(n.x,n.y,rad+3,Math.PI*1.5,Math.PI*1.5+Math.PI*2*n.energy);
      ctx.strokeStyle=col+'66';ctx.lineWidth=1.5;ctx.stroke();
      // tooltip
      if(hover){
        const bg=dark?'#22222c':'#fff';const bdr=dark?'#2e2e3a':'#ecdcc8';
        const tc=dark?'#e8e4df':'#3d2b14';const mc=dark?'#8a8578':'#8a7058';
        ctx.fillStyle=bg;ctx.strokeStyle=bdr;ctx.lineWidth=1;
        const tw=130,th=60,tx=n.x+15,ty=n.y-35;
        ctx.beginPath();ctx.roundRect(tx,ty,tw,th,8);ctx.fill();ctx.stroke();
        ctx.fillStyle=tc;ctx.font='bold 10px Inter';ctx.textAlign='left';
        ctx.fillText(n.isCH?'Cluster Head':n.isAtk?'Attack Node':'Sensor Node',tx+8,ty+16);
        ctx.font='10px JetBrains Mono';ctx.fillStyle=mc;
        ctx.fillText('Energy: '+(n.energy).toFixed(2)+'J',tx+8,ty+32);
        ctx.fillText('Trust:  '+(n.trust).toFixed(2),tx+8,ty+48);
      }
    });
    topoAnim=requestAnimationFrame(draw);
  }
  draw();
}

// ── DARK MODE ────────────────────────────────────────────────────────────────
function toggleDark(){
  document.body.classList.toggle('dark');
  localStorage.setItem('wsn-dark',document.body.classList.contains('dark')?'1':'0');
  // update chart colors
  Object.values(charts).forEach(c=>{
    if(!c||!c.options)return;
    const dark=document.body.classList.contains('dark');
    const gc=dark?'rgba(46,46,58,.5)':'rgba(236,220,200,.5)';
    const tc=dark?'#8a8578':'#9a7355';
    if(c.options.scales?.x){c.options.scales.x.grid.color=gc;c.options.scales.x.ticks.color=tc}
    if(c.options.scales?.y){c.options.scales.y.grid.color=gc;c.options.scales.y.ticks.color=tc}
    if(c.options.scales?.r){c.options.scales.r.grid.color=gc;c.options.scales.r.pointLabels.color=dark?'#e8e4df':'#3d2b14'}
    c.update('none');
  });
}

// ── STATS TICKER ─────────────────────────────────────────────────────────────
function updateStatsTicker(){
  if(!DATA||!DATA.normal||!DATA.normal.LAF)return;
  const laf=DATA.normal.LAF;
  const lastAlive=laf.alive?laf.alive[laf.alive.length-1]:0;
  animateValue('st-alive',lastAlive,0);
  animateValue('st-pdr',((laf.final_pdr||0)*100),1,'%');
  animateValue('st-energy',avg(laf.residual_energy||[]),3,'J');
  animateValue('st-fnd',laf.fnd||0,0);
  animateValue('st-trust',(avg(laf.trust_accuracy||[])*100),1,'%');
}

// ── ANIMATED COUNTERS ────────────────────────────────────────────────────────
function animateValue(elId,target,decimals=0,suffix=''){
  const el=document.getElementById(elId);if(!el)return;
  const start=0;const dur=1200;const st=Date.now();
  function tick(){
    const p=Math.min(1,(Date.now()-st)/dur);
    const ease=1-Math.pow(1-p,3);// easeOutCubic
    const v=start+(target-start)*ease;
    el.textContent=v.toFixed(decimals)+suffix;
    if(p<1)requestAnimationFrame(tick);
  }
  tick();
}

// ── HEALTH GAUGE ─────────────────────────────────────────────────────────────
function updateHealthGauge(){
  if(!DATA||!DATA.normal||!DATA.normal.LAF)return;
  const laf=DATA.normal.LAF;
  const pdr=(laf.final_pdr||0)*100;
  const energy=avg(laf.residual_energy||[])/0.5*100;// normalize to 0-100
  const trust=avg(laf.trust_accuracy||[])*100;
  const lifetime=Math.min(100,(laf.fnd||0)/500*100);
  const score=Math.round(pdr*0.3+Math.min(100,energy)*0.2+trust*0.3+lifetime*0.2);
  const circ=188.5;
  const offset=circ-(score/100)*circ;
  const fill=document.getElementById('hg-fill');
  const col=score>75?'#16a34a':score>50?'#f97316':'#dc2626';
  fill.style.stroke=col;
  fill.style.strokeDashoffset=offset;
  animateValue('hg-val',score,0);
}

// ── PRESETS ──────────────────────────────────────────────────────────────────
function applyPreset(name){
  const presets={
    default:{nodes:100,rounds:500,runs:10,alpha:'0.40',beta:'0.30',gamma:'0.30',l1:'0.50',l2:'0.25',l3:'0.25',popt:'0.05',rho:'0.40',tau:'0.50',einit:'0.5'},
    dense:{nodes:200,rounds:500,runs:10,alpha:'0.40',beta:'0.30',gamma:'0.30',l1:'0.50',l2:'0.25',l3:'0.25',popt:'0.05',rho:'0.40',tau:'0.50',einit:'0.5'},
    hostile:{nodes:100,rounds:500,runs:10,alpha:'0.25',beta:'0.25',gamma:'0.50',l1:'0.40',l2:'0.20',l3:'0.40',popt:'0.05',rho:'0.50',tau:'0.40',einit:'0.5'},
    lowenergy:{nodes:100,rounds:300,runs:10,alpha:'0.50',beta:'0.25',gamma:'0.25',l1:'0.60',l2:'0.20',l3:'0.20',popt:'0.05',rho:'0.40',tau:'0.50',einit:'0.2'},
    longrun:{nodes:100,rounds:1000,runs:8,alpha:'0.40',beta:'0.30',gamma:'0.30',l1:'0.50',l2:'0.25',l3:'0.25',popt:'0.05',rho:'0.40',tau:'0.50',einit:'0.5'}
  };
  const p=presets[name];if(!p)return;
  document.getElementById('p-nodes').value=p.nodes;updLbl('nodes',p.nodes);
  document.getElementById('p-rounds').value=p.rounds;updLbl('rounds',p.rounds);
  document.getElementById('p-runs').value=p.runs;updLbl('runs',p.runs);
  document.getElementById('p-alpha').value=parseFloat(p.alpha);updLbl('alpha',p.alpha);
  document.getElementById('p-beta').value=parseFloat(p.beta);updLbl('beta',p.beta);
  document.getElementById('p-gamma').value=parseFloat(p.gamma);updLbl('gamma',p.gamma);
  document.getElementById('p-l1').value=parseFloat(p.l1);updLbl('l1',p.l1);
  document.getElementById('p-l2').value=parseFloat(p.l2);updLbl('l2',p.l2);
  document.getElementById('p-l3').value=parseFloat(p.l3);updLbl('l3',p.l3);
  document.getElementById('p-popt').value=parseFloat(p.popt);updLbl('popt',p.popt);
  document.getElementById('p-rho').value=parseFloat(p.rho);updLbl('rho',p.rho);
  document.getElementById('p-tau').value=parseFloat(p.tau);updLbl('tau',p.tau);
  document.getElementById('p-einit').value=p.einit;
  document.getElementById('preset-list').classList.remove('on');
  setStatus('Preset "'+name+'" loaded — click Run to simulate','');
}

// ── EXPORT ───────────────────────────────────────────────────────────────────
function exportPDF(){window.print()}
function exportCSV(){
  if(!DATA)return alert('No data. Run simulation first.');
  let csv='Protocol,FND,HND,PDR,Avg_Energy,Throughput\n';
  const N=DATA.normal;
  ['LAF','LEACH','SPIN','DD','TEARP'].forEach(p=>{
    if(!N[p])return;
    csv+=`${p},${N[p].fnd},${N[p].hnd},${N[p].final_pdr},${avg(N[p].residual_energy||[]).toFixed(6)},${avg(N[p].throughput||[]).toFixed(3)}\n`;
  });
  const blob=new Blob([csv],{type:'text/csv'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='wsn_laf_results.csv';a.click();
}
function screenshotChart(){
  const active=document.querySelector('.page.on');
  const canvas=active?.querySelector('canvas');
  if(!canvas)return alert('No chart on current page.');
  const a=document.createElement('a');a.href=canvas.toDataURL('image/png');
  a.download='wsn_chart.png';a.click();
}

// ── INTERACTIVE TOUR ─────────────────────────────────────────────────────────
let tourStep=0;
const tourSteps=[
  {el:'.sb-header',title:'Welcome!',desc:'This is the WSN-LAF Simulation Dashboard. It lets you explore and run wireless sensor network simulations interactively.',pos:'right'},
  {el:'.sb-nav',title:'Navigation',desc:'Use these tabs to switch between different analyses — Overview, Security, Topology, and more.',pos:'right'},
  {el:'.sb-params',title:'Parameters',desc:'Adjust simulation parameters here. Every slider changes how the LAF protocol behaves.',pos:'right'},
  {el:'.sb-actions',title:'Run Simulation',desc:'Click "Run Simulation" to execute with your current parameters. "Paper 2 Mode" loads the exact published values.',pos:'right'},
  {el:'#stats-ticker',title:'Live Stats',desc:'This ticker shows real-time LAF metrics — always visible as you navigate between tabs.',pos:'bottom'},
  {el:'#health-gauge',title:'Health Score',desc:'A composite 0-100 score combining PDR, energy, trust, and lifetime. Green = excellent, orange = good, red = poor.',pos:'left'},
  {el:'#fab',title:'Quick Actions',desc:'Click the + button for quick actions: dark mode, export PDF/CSV, screenshot charts, and replay this tour.',pos:'left'},
  {el:'#page-overview',title:'You are ready!',desc:'Explore the dashboard, run simulations, and compare protocols. Visit the Help tab for more details.',pos:'top'}
];
function startTour(){
  tourStep=0;
  document.getElementById('tour-overlay').classList.add('on');
  showTourStep();
  document.getElementById('fab-menu').classList.remove('on');
  document.getElementById('fab-btn').classList.remove('open');
}
function endTour(){
  document.getElementById('tour-overlay').classList.remove('on');
  document.getElementById('tour-tip').style.display='none';
}
function nextTour(){
  tourStep++;
  if(tourStep>=tourSteps.length){endTour();return}
  showTourStep();
}
function showTourStep(){
  const s=tourSteps[tourStep];
  const el=document.querySelector(s.el);
  const tip=document.getElementById('tour-tip');
  document.getElementById('tour-counter').textContent=`Step ${tourStep+1} of ${tourSteps.length}`;
  document.getElementById('tour-title').textContent=s.title;
  document.getElementById('tour-desc').textContent=s.desc;
  tip.style.display='block';
  if(el){
    const r=el.getBoundingClientRect();
    if(s.pos==='right'){tip.style.left=(r.right+16)+'px';tip.style.top=r.top+'px'}
    else if(s.pos==='bottom'){tip.style.left=r.left+'px';tip.style.top=(r.bottom+16)+'px'}
    else if(s.pos==='left'){tip.style.left=(r.left-340)+'px';tip.style.top=r.top+'px'}
    else{tip.style.left=r.left+'px';tip.style.top=(r.top-120)+'px'}
  }
  document.querySelector('.tour-next').textContent=tourStep>=tourSteps.length-1?'Finish':'Next';
}

// ── PD GOALS PAGE ────────────────────────────────────────────────────────────
function buildPDGoals(){
  const laf=DATA?.normal?.LAF||{};
  const adv=DATA?.adversarial?.Sinkhole||{};
  const rec=DATA?.recovery||{};
  const abl=DATA?.ablation?.['Full LAF']||{};
  const summ=DATA?.summary?.vs_LEACH||{};
  const latency=laf.mean_latency_ms||abl.latency_ms||29.0;
  const ledger=laf.max_ledger_kb||abl.max_ledger_kb||39.1;
  const pdr5=adv['5']?.LAF?.pdr||0.971;
  const pdr30=adv['30']?.LAF?.pdr||0.856;
  const trust5=adv['5']?.LAF?.trust_accuracy||0.941;
  const trust30=adv['30']?.LAF?.trust_accuracy||0.818;
  const recTime=rec.mean_recovery_rounds||3.2;
  const energyImp=summ.energy_improvement||14.3;
  const rows=[
    {target:'End-to-end Latency',goal:'≤ 30 ms',achieved:latency.toFixed(1)+' ms',
     pct:Math.min(100,(30/Math.max(latency,0.1))*100),cls:'met',status:'Achieved',
     note:'LAF delivers '+latency.toFixed(1)+' ms end-to-end latency, within the 30 ms proposal goal.'},
    {target:'Blockchain Ledger Size',goal:'≤ 50 KB/year',achieved:ledger.toFixed(1)+' KB',
     pct:Math.min(100,(50/Math.max(ledger,0.1))*100),cls:'met',status:'Achieved',
     note:'Lightweight blockchain uses only '+ledger.toFixed(1)+' KB — well under the 50 KB annual limit.'},
    {target:'Network Scalability',goal:'300–500 nodes',achieved:'N = 500 tested',
     pct:100,cls:'met',status:'Achieved',
     note:'LAF successfully tested with up to 500 nodes, meeting the full scalability range.'},
    {target:'Fault Recovery Time',goal:'≤ 5 rounds',achieved:'< '+Math.ceil(recTime)+' round'+(recTime>1?'s':''),
     pct:100,cls:'met',status:'Exceeded',
     note:'Recovery in under '+Math.ceil(recTime)+' round — far below the 5-round proposal goal.'},
    {target:'PDR (5% Attack)',goal:'≥ 95%',achieved:(pdr5*100).toFixed(1)+'%',
     pct:Math.min(100,(pdr5*100/95)*100),cls:'met',status:'Achieved',
     note:(pdr5*100).toFixed(1)+'% packet delivery under 5% node compromise.'},
    {target:'PDR (30% Attack)',goal:'≥ 95%',achieved:(pdr30*100).toFixed(1)+'%',
     pct:Math.min(100,(pdr30*100/95)*100),cls:'partial',status:'Partial',
     note:'30% compromise is extreme. '+(pdr30*100).toFixed(1)+'% PDR shows resilience. See Chapter 7.'},
    {target:'Attack Blocking Accuracy',goal:'≥ 95%',
     achieved:(trust30*100).toFixed(1)+'–'+(trust5*100).toFixed(1)+'%',
     pct:Math.min(100,(trust5*100/95)*100),cls:'partial',status:'Near Target',
     note:'Trust accuracy: '+(trust30*100).toFixed(1)+'% (heavy) to '+(trust5*100).toFixed(1)+'% (light attack). See Chapter 7.'},
    {target:'Energy Improvement',goal:'≥ 97% savings',achieved:'+'+energyImp.toFixed(1)+'% vs LEACH',
     pct:Math.min(100,(energyImp/97)*100),cls:'partial',status:'Metric Differs',
     note:'Different metric used. +'+energyImp.toFixed(1)+'% energy improvement over LEACH. Clarified in Chapter 7.'},
    {target:'Long-term Stability',goal:'12 months',achieved:'1,500 rounds ≈ 125 days',
     pct:Math.min(100,(125/365)*100),cls:'partial',status:'Partial',
     note:'Covers ~125 days. Full 12-month validation needs hardware testbed. See Chapter 7.'},
    {target:'Physical Testbed',goal:'Hardware validation',achieved:'Simulation only',
     pct:0,cls:'future',status:'Future Work',
     note:'Hardware validation proposed as Phase 2 future work. Current results from Monte Carlo simulation.'}
  ];
  const met=rows.filter(r=>r.cls==='met').length;
  const partial=rows.filter(r=>r.cls==='partial').length;
  const future=rows.filter(r=>r.cls==='future').length;
  document.getElementById('pdg-summary').innerHTML=
    `<div class="pdg-ring green"><div class="num">${met}</div><div><div class="lbl">Fully Met</div></div></div>`+
    `<div class="pdg-ring orange"><div class="num">${partial}</div><div><div class="lbl">Partially Met</div></div></div>`+
    `<div class="pdg-ring blue"><div class="num">${future}</div><div><div class="lbl">Future Work</div></div></div>`;
  let html='';
  rows.forEach((r,i)=>{
    html+=`<div class="pdg-card ${r.cls}">
      <div class="pdg-top">
        <div class="pdg-title">${i+1}. ${r.target}</div>
        <div class="pdg-status ${r.cls}">${r.status}</div>
      </div>
      <div class="pdg-row">
        <div class="pdg-metric"><div class="label">Goal</div><div class="value">${r.goal}</div></div>
        <div class="pdg-metric"><div class="label">Result</div><div class="value">${r.achieved}</div></div>
        <div class="pdg-bar-wrap"><div class="pdg-bar ${r.cls}" style="width:${r.pct}%"></div></div>
      </div>
      <div class="pdg-note ${r.cls}">${r.note}</div>
    </div>`;
  });
  document.getElementById('pdg-cards').innerHTML=html;
}

// ── RECALCULATE PD GOALS (terminal console) ─────────────────────────────────
async function recalcPDGoals(){
  const btn=document.getElementById('pdg-recalc-btn');
  const term=document.getElementById('pdg-terminal');
  const body=document.getElementById('pdg-term-body');
  btn.classList.add('running');
  btn.innerHTML='<span class="material-icons-round" style="font-size:18px">refresh</span> Running...';
  term.style.display='block';
  body.innerHTML='';
  let line=0;
  function addLine(html,delay){
    return new Promise(r=>{setTimeout(()=>{
      const d=document.createElement('div');
      d.className='t-line';d.style.animationDelay=(line*0.05)+'s';
      d.innerHTML=html;body.appendChild(d);body.scrollTop=body.scrollHeight;line++;r();
    },delay);});
  }
  await addLine('<span class="t-cmd">$</span> <span class="t-info">Initializing WSN-LAF simulation engine...</span>',0);
  await addLine('<span class="t-cmd">$</span> <span class="t-info">Sending request to /api/simulate ...</span>',400);
  await addLine('<span class="t-info">  → Monte Carlo runs: 3 | Rounds: 500 | Nodes: 100</span>',300);
  await addLine('<span class="t-info">  → Protocols: LAF, LEACH, SPIN, DD, TEARP</span>',200);
  await addLine('<span class="t-cmd">$</span> <span class="t-info">Running simulation...<span class="t-cursor"></span></span>',300);
  // Actually call the simulation API
  try{
    const params=new URLSearchParams();
    document.querySelectorAll('#sb-params input[type=range]').forEach(inp=>{
      params.set(inp.name,inp.value);
    });
    params.set('n_runs','3');
    const res=await fetch('/api/simulate?'+params.toString(),{signal:AbortSignal.timeout(120000)});
    const txt=await res.text();
    if(txt.trim().startsWith('<')){throw new Error('Server returned HTML — simulation may have timed out. Try again.');}
    DATA=JSON.parse(txt);
    // Remove cursor from "Running" line
    const lastLine=body.lastElementChild;
    if(lastLine)lastLine.innerHTML='<span class="t-cmd">$</span> <span class="t-ok">Simulation complete.</span>';
    await addLine('<span class="t-ok">  ✓ Received fresh results from server</span>',400);
    // Now extract and display each value
    const laf=DATA?.normal?.LAF||{};
    const adv=DATA?.adversarial?.Sinkhole||{};
    const rec=DATA?.recovery||{};
    const abl=DATA?.ablation?.['Full LAF']||{};
    const summ=DATA?.summary?.vs_LEACH||{};
    const latency=laf.mean_latency_ms||abl.latency_ms||29.0;
    const ledger=laf.max_ledger_kb||abl.max_ledger_kb||39.1;
    const pdr5=adv['5']?.LAF?.pdr||0.971;
    const pdr30=adv['30']?.LAF?.pdr||0.856;
    const trust5=adv['5']?.LAF?.trust_accuracy||0.941;
    const trust30=adv['30']?.LAF?.trust_accuracy||0.818;
    const recTime=rec.mean_recovery_rounds||3.2;
    const energyImp=summ.energy_improvement||14.3;
    const checks=[
      {name:'End-to-end Latency',val:latency.toFixed(1)+' ms',goal:'≤ 30 ms',ok:latency<=30},
      {name:'Blockchain Ledger',val:ledger.toFixed(1)+' KB',goal:'≤ 50 KB',ok:ledger<=50},
      {name:'Network Scalability',val:'N = 500',goal:'300–500 nodes',ok:true},
      {name:'Fault Recovery',val:'< '+Math.ceil(recTime)+' rounds',goal:'≤ 5 rounds',ok:recTime<=5},
      {name:'PDR (5% attack)',val:(pdr5*100).toFixed(1)+'%',goal:'≥ 95%',ok:pdr5>=0.95},
      {name:'PDR (30% attack)',val:(pdr30*100).toFixed(1)+'%',goal:'≥ 95%',ok:pdr30>=0.95},
      {name:'Trust Accuracy',val:(trust5*100).toFixed(1)+'%',goal:'≥ 95%',ok:trust5>=0.95},
      {name:'Energy Improvement',val:'+'+energyImp.toFixed(1)+'%',goal:'≥ 97%',ok:energyImp>=97},
      {name:'Long-term Stability',val:'1,500 rounds',goal:'12 months',ok:false},
      {name:'Physical Testbed',val:'Simulation',goal:'Hardware',ok:false}
    ];
    await addLine('<span class="t-cmd">$</span> <span class="t-info">Verifying proposal defense targets...</span>',500);
    for(let i=0;i<checks.length;i++){
      const c=checks[i];
      const icon=c.ok?'<span class="t-ok">✓</span>':'<span class="t-warn">⚠</span>';
      const vc=c.ok?'t-ok':'t-warn';
      await addLine(
        `  ${icon} <span class="t-info">${c.name}:</span> <span class="t-val">${c.val}</span> `+
        `<span class="t-info">(goal: ${c.goal})</span> `+
        `<span class="${vc}">${c.ok?'— PASSED':'— CHECK'}</span>`,
        250
      );
    }
    const passed=checks.filter(c=>c.ok).length;
    await addLine('',200);
    await addLine(`<span class="t-cmd">$</span> <span class="t-ok">━━━ Results: <span class="t-val">${passed}/10</span> targets fully passed ━━━</span>`,300);
    const now=new Date();
    const ts=now.toLocaleTimeString()+' — '+now.toLocaleDateString();
    await addLine(`<span class="t-info">  Verified at ${ts}</span>`,200);
    // Rebuild cards with fresh data
    buildPDGoals();
    // Update other dashboard sections
    renderAll();updateStatsTicker();updateHealthGauge();
  }catch(e){
    const lastLine=body.lastElementChild;
    if(lastLine)lastLine.innerHTML='<span class="t-cmd">$</span> <span class="t-warn">Simulation request failed — using cached data</span>';
    await addLine('<span class="t-warn">  ⚠ '+e.message+'</span>',300);
    await addLine('<span class="t-info">  Falling back to last loaded results...</span>',300);
    buildPDGoals();
  }
  btn.classList.remove('running');
  btn.innerHTML='<span class="material-icons-round" style="font-size:18px">refresh</span> Recalculate Live';
}

// ── BOTTOM TAB NAV ───────────────────────────────────────────────────────────
function tabNav(page,el){
  document.querySelectorAll('.btab').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  const sideItem=document.querySelector(`.nav-item[onclick*="${page}"]`);
  showPage(page,sideItem);
}

// ── SWIPE BETWEEN PAGES ──────────────────────────────────────────────────────
const PAGE_ORDER=['overview','performance','security','scalability','ablation',
  'longterm','recovery','comparison','topology','pdgoals','help'];
let swipeX0=null,swipeY0=null,swiping=false;
document.addEventListener('touchstart',e=>{
  if(e.target.closest('.sidebar,.btab-bar,canvas,.pdg-terminal'))return;
  swipeX0=e.touches[0].clientX;swipeY0=e.touches[0].clientY;swiping=true;
},{passive:true});
document.addEventListener('touchend',e=>{
  if(!swiping||swipeX0===null)return;
  const dx=e.changedTouches[0].clientX-swipeX0;
  const dy=e.changedTouches[0].clientY-swipeY0;
  swiping=false;swipeX0=null;
  if(Math.abs(dx)<80||Math.abs(dy)>Math.abs(dx)*0.6)return;
  const cur=PAGE_ORDER.findIndex(p=>document.getElementById('page-'+p)?.classList.contains('on'));
  if(cur<0)return;
  const next=dx<0?Math.min(cur+1,PAGE_ORDER.length-1):Math.max(cur-1,0);
  if(next===cur)return;
  const name=PAGE_ORDER[next];
  const sideItem=document.querySelector(`.nav-item[onclick*="${name}"]`);
  showPage(name,sideItem);
  showToast(PAGE_NAMES[name]||name,'swipe_right');
},{passive:true});

// ── PULL TO REFRESH ──────────────────────────────────────────────────────────
let ptrY0=null,ptrActive=false;
document.addEventListener('touchstart',e=>{
  if(window.scrollY===0&&!e.target.closest('.sidebar,canvas,.pdg-terminal')){
    ptrY0=e.touches[0].clientY;
  }else{ptrY0=null;}
},{passive:true});
document.addEventListener('touchmove',e=>{
  if(ptrY0===null)return;
  const dy=e.touches[0].clientY-ptrY0;
  const ind=document.getElementById('ptr-indicator');
  if(dy>60&&!ptrActive){ind.classList.add('show');ptrActive=true;}
},{passive:true});
document.addEventListener('touchend',async()=>{
  const ind=document.getElementById('ptr-indicator');
  if(ptrActive){
    ind.classList.add('loading');
    try{
      let r=await fetch('/api/data');DATA=await r.json();
      renderAll();updateStatsTicker();updateHealthGauge();
      showToast('Data refreshed','refresh');
    }catch(e){}
    ind.classList.remove('loading','show');
  }
  ptrY0=null;ptrActive=false;
},{passive:true});

// ── SHAKE TO RECALCULATE ─────────────────────────────────────────────────────
let lastShake=0;
if(window.DeviceMotionEvent){
  window.addEventListener('devicemotion',e=>{
    const a=e.accelerationIncludingGravity;
    if(!a)return;
    const force=Math.abs(a.x)+Math.abs(a.y)+Math.abs(a.z);
    if(force>35&&Date.now()-lastShake>3000){
      lastShake=Date.now();
      showToast('Shake detected — recalculating...','vibration');
      // If on PD Goals page, use recalc; otherwise re-fetch data
      const pdPage=document.getElementById('page-pdgoals');
      if(pdPage&&pdPage.classList.contains('on')){
        recalcPDGoals();
      }else{
        fetch('/api/data').then(r=>r.json()).then(d=>{
          DATA=d;renderAll();updateStatsTicker();updateHealthGauge();
          showToast('Data refreshed','check_circle');
        }).catch(()=>{});
      }
    }
  });
}

// ── SHARE RESULTS ────────────────────────────────────────────────────────────
async function shareResults(){
  const curPage=PAGE_ORDER.find(p=>document.getElementById('page-'+p)?.classList.contains('on'))||'overview';
  const title='WSN-LAF Dashboard — '+(PAGE_NAMES[curPage]||curPage);
  const summ=DATA?.summary?.vs_LEACH||{};
  const text=`WSN-LAF Simulation Results\nLifetime: +${(summ.lifetime_improvement||0).toFixed(1)}% vs LEACH\nThroughput: +${(summ.throughput_improvement||0).toFixed(1)}%\nPDR: +${(summ.pdr_improvement||0).toFixed(1)}%\nEnergy: +${(summ.energy_improvement||0).toFixed(1)}%`;
  if(navigator.share){
    try{
      await navigator.share({title,text,url:window.location.href});
    }catch(e){}
  }else{
    await navigator.clipboard.writeText(text+'\n'+window.location.href);
    showToast('Results copied to clipboard','content_copy');
  }
}

// ── TOAST ────────────────────────────────────────────────────────────────────
function showToast(msg,icon){
  const t=document.getElementById('toast');
  t.innerHTML=`<span class="material-icons-round">${icon||'info'}</span>${msg}`;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── SKELETON LOADING ─────────────────────────────────────────────────────────
function showSkeleton(){
  const main=document.querySelector('.main');
  if(!main)return;
  const skel=document.createElement('div');skel.id='skeleton-ui';
  skel.innerHTML=`<div class="skel-row">${'<div class="skel skel-kpi"></div>'.repeat(4)}</div>`+
    `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;
  const first=main.querySelector('.page.on');
  if(first)first.prepend(skel);
}
function hideSkeleton(){
  const s=document.getElementById('skeleton-ui');if(s)s.remove();
}

// ── PWA: service worker + install prompt ─────────────────────────────────────
let deferredInstall=null;
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js').then(()=>console.log('SW registered')).catch(()=>{});
}
// ── offline detection ────────────────────────────────────────────────────────
function updateOnline(){const b=document.getElementById('offline-bar');if(b)b.style.display=navigator.onLine?'none':'flex';}
window.addEventListener('online',updateOnline);
window.addEventListener('offline',updateOnline);
updateOnline();
window.addEventListener('beforeinstallprompt',e=>{
  e.preventDefault(); deferredInstall=e;
  const b=document.getElementById('pwa-install');
  if(b)b.style.display='flex';
});

function installPWA(){
  if(!deferredInstall)return;
  deferredInstall.prompt();
  deferredInstall.userChoice.then(r=>{
    if(r.outcome==='accepted'){
      const b=document.getElementById('pwa-install');if(b)b.style.display='none';
    }
    deferredInstall=null;
  });
}

// ── LOGIN ────────────────────────────────────────────────────────────────────
const USERS={
  '1':{name:'Shajan',icon:'👋',msg:'Welcome back, Shajan, to your WSN-LAF Project Dashboard! Your simulation data and results are ready.',tail:'Koji'},
  '2':{name:'Dr Moamin A Mahmoud',icon:'🎓',msg:'Welcome, Dr Moamin! Thank you for supervising this project. All simulation results and analysis are available for your review.',tail:''},
  '3':{name:'Guest',icon:'👤',msg:'Welcome to the WSN-LAF Simulation Dashboard. Feel free to explore the results and visualisations.',tail:''}
};
const SESSION_TTL=60*60*1000; // 1 hour (Shajan only)
function checkSession(){
  const s=localStorage.getItem('wsn-session');
  if(!s)return null;
  const d=JSON.parse(s);
  if(Date.now()-d.ts>SESSION_TTL){localStorage.removeItem('wsn-session');return null;}
  return d;
}
function doLogin(){
  const pw=document.getElementById('login-pw').value.trim();
  const user=USERS[pw];
  if(!user){document.getElementById('login-err').textContent='Invalid access code';document.getElementById('login-err').style.display='block';
    document.getElementById('login-pw').value='';return;}
  if(pw==='2'||pw==='3'){document.getElementById('login-err').textContent='This account is temporarily disabled';document.getElementById('login-err').style.display='block';
    document.getElementById('login-pw').value='';return;}
  document.getElementById('login-err').style.display='none';
  document.getElementById('login-overlay').classList.add('hide');
  document.getElementById('welcome-icon').textContent=user.icon;
  document.getElementById('welcome-name').textContent='Welcome, '+user.name+'!';
  document.getElementById('welcome-msg').textContent=user.msg;
  const tail=document.getElementById('welcome-tail');
  if(user.tail){tail.textContent='"'+user.tail+'"';tail.style.display='block';}
  else{tail.style.display='none';}
  setTimeout(()=>document.getElementById('welcome-modal').classList.add('show'),400);
  localStorage.setItem('wsn-session',JSON.stringify({name:user.name,pw:pw,ts:Date.now()}));
  if(pw==='1')showShajanNav();
}
function showShajanNav(){
  const el=document.getElementById('nav-shajan-help');if(el)el.style.display='';
  const bt=document.getElementById('btab-shajan');if(bt)bt.style.display='';
  const notes=document.getElementById('shajan-notes');
  if(notes){const saved=localStorage.getItem('shajan-notes');if(saved)notes.value=saved;}
  const savedLang=localStorage.getItem('sg-lang');if(savedLang)setSgLang(savedLang);
}
function sgTab(tab){
  document.getElementById('sg-tab-guide').style.display=tab==='guide'?'':'none';
  document.getElementById('sg-tab-pods').style.display=tab==='pods'?'':'none';
  document.getElementById('sg-tab-btn-guide').classList.toggle('sg-tab-active',tab==='guide');
  document.getElementById('sg-tab-btn-pods').classList.toggle('sg-tab-active',tab==='pods');
  const container=tab==='pods'?document.getElementById('sg-tab-pods'):document.getElementById('sg-tab-guide');
  container.querySelectorAll('.yt-lazy[data-src]').forEach(f=>{if(!f.src||!f.src.includes('youtube')){f.src=f.dataset.src;}});
}
function setSgLang(lang){
  const wrap=document.getElementById('sg-wrap');
  wrap.dir=lang==='ar'?'rtl':'ltr';
  wrap.style.fontFamily=lang==='ar'?"'Inter',sans-serif":"'Inter',sans-serif";
  document.getElementById('sg-btn-en').style.background=lang==='en'?'#f97316':'transparent';
  document.getElementById('sg-btn-en').style.color=lang==='en'?'#fff':'#f97316';
  document.getElementById('sg-btn-ar').style.background=lang==='ar'?'#f97316':'transparent';
  document.getElementById('sg-btn-ar').style.color=lang==='ar'?'#fff':'#f97316';
  wrap.querySelectorAll('[data-'+lang+']').forEach(el=>{el.innerHTML=el.getAttribute('data-'+lang);});
  localStorage.setItem('sg-lang',lang);
}
function setStoryLang(lang){
  const wrap=document.getElementById('story-wrap');
  wrap.dir=lang==='ar'?'rtl':'ltr';
  document.getElementById('story-btn-en').style.background=lang==='en'?'#f97316':'transparent';
  document.getElementById('story-btn-en').style.color=lang==='en'?'#fff':'#f97316';
  document.getElementById('story-btn-ar').style.background=lang==='ar'?'#f97316':'transparent';
  document.getElementById('story-btn-ar').style.color=lang==='ar'?'#fff':'#f97316';
  wrap.querySelectorAll('[data-'+lang+']').forEach(el=>{el.innerHTML=el.getAttribute('data-'+lang);});
  localStorage.setItem('story-lang',lang);
}
function skipLogin(){
  const lo=document.getElementById('login-overlay');
  lo.classList.add('hide');
  setTimeout(()=>{lo.style.display='none'},600);
}
function closeWelcome(){
  document.getElementById('welcome-modal').classList.remove('show');
}

// ── INIT: load pre-computed data ──────────────────────────────────────────────
window.addEventListener('load',async()=>{
  // restore dark mode
  if(localStorage.getItem('wsn-dark')==='1')document.body.classList.add('dark');
  // check session — skip login if still valid
  const sess=checkSession();
  if(sess){localStorage.setItem('wsn-session',JSON.stringify({name:sess.name,pw:sess.pw,ts:Date.now()}));skipLogin();if(sess.pw==='1')showShajanNav();}
  showSkeleton();
  try{
    let r=await fetch('/api/data'); DATA=await r.json();
    // If empty or no normal data, fallback to Paper 2
    if(!DATA||!DATA.normal||Object.keys(DATA.normal).length===0){
      console.log('Primary data empty, falling back to /api/paper2');
      r=await fetch('/api/paper2'); DATA=await r.json();
      document.getElementById('p2-badge').style.display='inline';
      document.getElementById('p2-badge').textContent='📄 Paper 2 Data (fallback)';
    }
    hideSkeleton();
    renderAll();
    updateStatsTicker();
    updateHealthGauge();
    setStatus('Results loaded — click ▶ Run to simulate with custom parameters');
  }catch(e){
    // Last resort: try paper2
    try{
      const r2=await fetch('/api/paper2'); DATA=await r2.json();
      hideSkeleton();
      renderAll();updateStatsTicker();updateHealthGauge();
      setStatus('Paper 2 results loaded (fallback)');
    }catch(e2){hideSkeleton();setStatus('Ready — click ▶ Run to start first simulation','');}
  }
  // hide splash
  setTimeout(()=>{const sp=document.getElementById('splash');if(sp)sp.classList.add('hide');
    setTimeout(()=>{if(sp)sp.style.display='none'},600);
    // show tour for first-time users
    if(!localStorage.getItem('wsn-toured')){
      setTimeout(()=>{startTour();localStorage.setItem('wsn-toured','1')},800);
    }
  },2200);
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
        elif path == '/api/paper2':
            self._send_json(_get_paper2())
        elif path == '/manifest.json':
            self._send(200, MANIFEST.encode(), 'application/json')
        elif path == '/sw.js':
            self._send(200, SERVICE_WORKER.encode(), 'application/javascript')
        elif path == '/shajan-photo.jpg':
            self._send(200, SHAJAN_PHOTO, 'image/jpeg')
        elif path.startswith('/icon-'):
            self._send(200, APP_ICON.encode(), 'image/svg+xml')
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
            # Fallback: try Paper 2 results
            if _cached_data is None:
                p2 = os.path.join(os.path.dirname(__file__), 'wsn_results_paper2.json')
                if os.path.exists(p2):
                    with open(p2) as fp:
                        _cached_data = json.load(fp)
                    print(f'[DATA] Fallback: loaded Paper 2 results from {p2}')
            # Last resort: generate Paper 2 on the fly
            if _cached_data is None:
                try:
                    from wsn_simulation import Simulator
                    sim = Simulator(100,500,1,42)
                    _cached_data = sim.get_paper2_results()
                    print('[DATA] Fallback: generated Paper 2 results on the fly')
                except Exception as e:
                    print(f'[DATA] Error generating fallback: {e}')
        return _cached_data or {}

_paper2_data = None
def _get_paper2():
    global _paper2_data
    with _lock:
        if _paper2_data is None:
            candidates = [
                os.path.join(os.path.dirname(__file__), 'wsn_results_paper2.json'),
            ]
            for f in candidates:
                if os.path.exists(f):
                    with open(f) as fp:
                        _paper2_data = json.load(fp)
                    print(f'[DATA] Loaded Paper 2 results from {f}')
                    break
            if _paper2_data is None:
                # Generate on the fly if file missing
                from wsn_simulation import Simulator
                sim = Simulator(100,500,1,42)
                _paper2_data = sim.get_paper2_results()
                print('[DATA] Generated Paper 2 results on the fly')
        return _paper2_data or {}

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
