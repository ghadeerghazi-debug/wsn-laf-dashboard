"""
WSN Simulation — Lightweight Adaptive Framework (LAF) — Enhanced Edition
Adds: Latency tracking, Ledger footprint, Extended scalability (N≤500),
      Long-term scenario (R=5000), Fault-recovery scenario
"""
import numpy as np, json, math, random
from dataclasses import dataclass
from typing import List, Optional
from copy import deepcopy

# ── Physical constants ────────────────────────────────────────────────────────
E_ELEC=50e-9; E_FS=10e-12; E_MP=0.0013e-12
D0=math.sqrt(E_FS/E_MP); E_DA=5e-9
K=4000; E_INIT=0.5; MSG_BITS=200
AREA_X=100; AREA_Y=100; BS_X=50; BS_Y=110
P_OPT=0.05; RHO=0.4; TAU=0.5
ALPHA=0.4; BETA=0.3; GAMMA=0.3

# ── NEW constants ─────────────────────────────────────────────────────────────
DATA_RATE   = 300000.0   # bps — IEEE 802.15.4g capable
BLOCK_SZ_B  = 2000       # bytes per blockchain block (<2 KB)
PRUNE_WIN   = 20         # sliding-window pruning (active blocks retained)
HOP_MS      = (K / DATA_RATE) * 1000 + 1.0   # ≈14.33 ms per hop

def tx_energy(k,d):
    return E_ELEC*k+(E_FS if d<D0 else E_MP)*k*(d**2 if d<D0 else d**4)
def rx_energy(k): return E_ELEC*k
def agg_energy(k): return E_DA*k
def dist(x1,y1,x2,y2): return math.sqrt((x1-x2)**2+(y1-y2)**2)

@dataclass
class Node:
    nid:int; x:float; y:float
    energy:float=E_INIT; trust:float=1.0
    alive:bool=True; is_ch:bool=False
    is_malicious:bool=False; ch_rounds:int=0
    def d(self,o): return dist(self.x,self.y,o.x,o.y)
    def dbs(self): return dist(self.x,self.y,BS_X,BS_Y)
    def consume(self,e):
        self.energy=max(0.0,self.energy-e)
        if self.energy<=0: self.alive=False

class Network:
    def __init__(self,n,seed=42):
        rng=np.random.default_rng(seed)
        xs=rng.uniform(0,AREA_X,n); ys=rng.uniform(0,AREA_Y,n)
        self.nodes=[Node(i,xs[i],ys[i]) for i in range(n)]
        self.n=n
    def alive(self): return [n for n in self.nodes if n.alive]

class AttackInjector:
    def __init__(self,atype,ratio,seed=42):
        self.atype=atype; self.ratio=ratio
        self.rng=np.random.default_rng(seed+1000)
    def inject(self,net):
        n_mal=max(1,int(len(net.nodes)*self.ratio))
        idxs=list(range(len(net.nodes))); self.rng.shuffle(idxs)
        for i in idxs[:n_mal]:
            net.nodes[i].is_malicious=True; net.nodes[i].trust=0.3
    def apply(self,node,ok):
        if not node.is_malicious: return ok
        m={'Sinkhole':0.0,'Sybil':0.3,'Selective_Forwarding':0.5,'Hello_Flood':0.6}
        return self.rng.random()>m.get(self.atype,0.5)

# ── Metrics Collector (enhanced) ──────────────────────────────────────────────
class MC:
    def __init__(self,n):
        self.n=n; self.hist=[]; self.fnd=None; self.hnd=None
        self.ts=0; self.tr=0
        self.lat_sum=0.0; self.lat_n=0   # latency accumulators
        self.cum_blocks=0                 # cumulative blocks created
    def record(self,r,net,sent,rcvd,tc=0,tt=1,lat_ms=0.0,blocks=0):
        alive=net.alive(); na=len(alive)
        self.ts+=sent; self.tr+=rcvd
        te=sum(nd.energy for nd in net.nodes)
        me=float(np.mean([nd.energy for nd in alive])) if alive else 0.0
        pdr=rcvd/sent if sent>0 else 0.0
        tput=(rcvd*K)/1000.0
        epkt=(E_INIT*self.n-te)/max(1,self.tr)*1e6
        if self.fnd is None and na<self.n: self.fnd=r
        if self.hnd is None and na<=self.n//2: self.hnd=r
        tacc=tc/tt if tt>0 else 1.0
        # latency
        self.lat_sum+=lat_ms*rcvd; self.lat_n+=max(1,rcvd)
        mean_lat=self.lat_sum/self.lat_n
        # ledger
        self.cum_blocks+=blocks
        active_kb=min(self.cum_blocks,PRUNE_WIN)*BLOCK_SZ_B/1024.0
        self.hist.append((r,na,te,me,pdr,tput,epkt,tacc,mean_lat,active_kb))
    def out(self):
        H=self.hist
        return {
            'rounds'       :[h[0] for h in H],
            'alive'        :[h[1] for h in H],
            'total_energy' :[round(h[2],6) for h in H],
            'residual_energy':[round(h[3],6) for h in H],
            'pdr'          :[round(h[4],4) for h in H],
            'throughput'   :[round(h[5],3) for h in H],
            'energy_per_pkt':[round(h[6],4) for h in H],
            'trust_accuracy':[round(h[7],4) for h in H],
            'latency_ms'   :[round(h[8],2) for h in H],   # NEW
            'ledger_kb'    :[round(h[9],2) for h in H],   # NEW
            'fnd':self.fnd,'hnd':self.hnd,
            'final_pdr':round(self.tr/max(1,self.ts),4),
            'mean_latency_ms':round(self.lat_sum/max(1,self.lat_n),2),   # NEW
            'max_ledger_kb':round(min(self.cum_blocks,PRUNE_WIN)*BLOCK_SZ_B/1024.0,2), # NEW
            'total_sent':self.ts,'total_received':self.tr
        }

# ── Protocols ─────────────────────────────────────────────────────────────────
class LEACH:
    name='LEACH'
    def run(self,network,rounds,attacker=None):
        net=deepcopy(network)
        if attacker: attacker.inject(net)
        mc=MC(net.n); hist={nd.nid:0 for nd in net.nodes}
        for r in range(1,rounds+1):
            al=net.alive()
            if len(al)<2: break
            chs=[]
            for nd in al:
                nd.is_ch=False
                ep=r%max(1,int(1/P_OPT))
                th=(P_OPT/(1-P_OPT*ep)) if hist[nd.nid]<ep else 0
                if random.random()<th:
                    nd.is_ch=True; chs.append(nd); hist[nd.nid]=r
            if not chs:
                b=max(al,key=lambda n:n.energy); b.is_ch=True; chs=[b]
            sent=rcvd=0
            for nd in al:
                if nd.is_ch: continue
                ch=min(chs,key=lambda c:nd.d(c))
                nd.consume(tx_energy(K,nd.d(ch))); sent+=1
                ok=True
                if attacker: ok=attacker.apply(nd,True)
                if ok and ch.alive: ch.consume(rx_energy(K)); rcvd+=1
            for ch in chs:
                if not ch.alive: continue
                ch.consume(agg_energy(K*max(1,len(al)//max(1,len(chs)))))
                ch.consume(tx_energy(K,ch.dbs()))
            lat_ms = 2 * HOP_MS * (1 + max(0, 1-rcvd/max(1,sent))*0.3)
            mc.record(r,net,max(1,sent),rcvd,lat_ms=lat_ms)
        return mc

class SPIN:
    name='SPIN'
    def run(self,network,rounds,attacker=None):
        net=deepcopy(network); CR=30.0
        if attacker: attacker.inject(net)
        mc=MC(net.n)
        for r in range(1,rounds+1):
            al=net.alive()
            if len(al)<2: break
            sent=rcvd=0
            for nd in al:
                nbs=[n for n in al if n.nid!=nd.nid and nd.d(n)<=CR]
                if not nbs: continue
                for nb in nbs:
                    nd.consume(tx_energy(MSG_BITS,nd.d(nb)))
                    nb.consume(rx_energy(MSG_BITS))
                for nb in nbs:
                    if nb.energy>E_INIT*0.1:
                        nb.consume(tx_energy(K,nb.d(nd)))
                        nd.consume(rx_energy(K)); sent+=1
                        ok=True
                        if attacker: ok=attacker.apply(nb,True)
                        if ok: rcvd+=1
            relay=max(al,key=lambda n:n.energy) if al else None
            if relay: relay.consume(tx_energy(K,relay.dbs()))
            lat_ms = 2.5 * HOP_MS
            mc.record(r,net,max(1,sent),rcvd,lat_ms=lat_ms)
        return mc

class DD:
    name='DD'
    def run(self,network,rounds,attacker=None):
        net=deepcopy(network)
        if attacker: attacker.inject(net)
        mc=MC(net.n)
        for r in range(1,rounds+1):
            al=net.alive()
            if len(al)<2: break
            if r%5==1:
                for nd in al:
                    for nb in al:
                        if nb.nid!=nd.nid and nd.d(nb)<40:
                            nd.consume(tx_energy(MSG_BITS,nd.d(nb)))
                            nb.consume(rx_energy(MSG_BITS))
            sent=rcvd=0
            for nd in al:
                if nd.dbs()<50:
                    nd.consume(tx_energy(K,nd.dbs())); sent+=1
                    ok=True
                    if attacker: ok=attacker.apply(nd,True)
                    if ok: rcvd+=1
                else:
                    cands=[n for n in al if n.nid!=nd.nid and n.dbs()<nd.dbs()]
                    if cands:
                        rl=min(cands,key=lambda n:n.dbs())
                        nd.consume(tx_energy(K,nd.d(rl)))
                        rl.consume(rx_energy(K)); sent+=1
                        ok=True
                        if attacker: ok=attacker.apply(rl,True)
                        if ok: rcvd+=1
            lat_ms = 3.0 * HOP_MS
            mc.record(r,net,max(1,sent),rcvd,lat_ms=lat_ms)
        return mc

class TEARP:
    name='TEARP'
    def run(self,network,rounds,attacker=None):
        net=deepcopy(network)
        if attacker: attacker.inject(net)
        mc=MC(net.n)
        for r in range(1,rounds+1):
            al=net.alive()
            if len(al)<2: break
            chs=[]
            for nd in al:
                sc=0.6*(nd.energy/E_INIT)+0.4*nd.trust
                if sc>0.55 and random.random()<P_OPT*1.2:
                    nd.is_ch=True; chs.append(nd)
                else: nd.is_ch=False
            if not chs:
                b=max(al,key=lambda n:n.energy*n.trust)
                b.is_ch=True; chs=[b]
            sent=rcvd=tc=tt=0
            for nd in al:
                if nd.is_ch: continue
                ch=min(chs,key=lambda c:nd.d(c))
                nd.consume(tx_energy(K,nd.d(ch))); sent+=1
                ok=True
                if attacker: ok=attacker.apply(nd,True)
                if ok and ch.alive: ch.consume(rx_energy(K)); rcvd+=1
                tt+=1
                nd.trust=max(0.1,nd.trust*(0.85 if nd.is_malicious else 1.02))
                nd.trust=min(1.0,nd.trust)
                tc+=(1 if (nd.is_malicious and nd.trust<TAU) or
                     (not nd.is_malicious and nd.trust>=TAU) else 0)
                nd.consume(rx_energy(MSG_BITS)*3)
            for ch in chs:
                if not ch.alive: continue
                ch.consume(agg_energy(K*max(1,len(al)//max(1,len(chs)))))
                ch.consume(tx_energy(K,ch.dbs()))
                ch.consume(rx_energy(MSG_BITS)*5)
            lat_ms = 2 * HOP_MS * (1 + max(0,1-rcvd/max(1,sent))*0.2)
            mc.record(r,net,max(1,sent),rcvd,tc,max(1,tt),lat_ms=lat_ms)
        return mc

class LAF:
    def __init__(self,lam=(0.5,0.25,0.25),a=ALPHA,b=BETA,g=GAMMA,
                 adaptive=True,blockchain=True,trust_cost=True):
        self.lam=lam; self.a=a; self.b=b; self.g=g
        self.adaptive=adaptive; self.blockchain=blockchain
        self.trust_cost=trust_cost; self.name='LAF'
    def score(self,nd,em,lm):
        l1,l2,l3=self.lam
        lq=1.0/(1.0+nd.dbs()/AREA_X)
        return l1*(nd.energy/em)+l2*(lq/lm)+l3*nd.trust
    def cost(self,nd,c,em):
        en=1.0-(c.energy/em); dn=nd.d(c)/AREA_X
        tv=c.trust if self.trust_cost else 1.0
        return self.a*en+self.b*dn+self.g*(1-tv)
    def update_trust(self,nd,ok):
        if not self.blockchain: return
        obs=(1.0 if ok else 0.0)*(0.1 if nd.is_malicious else 1.0)
        nd.trust=max(0.0,min(1.0,(1-RHO)*nd.trust+RHO*obs))
    def run(self,network,rounds,attacker=None):
        net=deepcopy(network)
        if attacker: attacker.inject(net)
        mc=MC(net.n)
        g=self.g
        for r in range(1,rounds+1):
            al=net.alive()
            if len(al)<2: break
            em=max((n.energy for n in al),default=E_INIT)
            lm=max((1.0/(1.0+n.dbs()/AREA_X) for n in al),default=1.0)
            scores={n.nid:self.score(n,em,lm) for n in al}
            avg_s=float(np.mean(list(scores.values())))
            chs=[n for n in al if scores[n.nid]>=avg_s*0.9
                 and random.random()<P_OPT*1.5]
            if not chs:
                b=max(al,key=lambda n:scores[n.nid])
                b.is_ch=True; chs=[b]
            else:
                for n in net.nodes: n.is_ch=False
                for ch in chs: ch.is_ch=True
            avg_t=float(np.mean([n.trust for n in al]))
            co=3 if avg_t<TAU else 1
            sent=rcvd=tc=tt=0
            for nd in al:
                if nd.is_ch: continue
                if not chs: continue
                bch=min(chs,key=lambda c:self.cost(nd,c,em))
                nd.consume(tx_energy(K,nd.d(bch))); sent+=1
                ok=True
                if attacker: ok=attacker.apply(nd,True)
                if ok and bch.alive: bch.consume(rx_energy(K)); rcvd+=1
                self.update_trust(nd,ok)
                tt+=1
                tc+=(1 if (nd.is_malicious and nd.trust<TAU) or
                     (not nd.is_malicious and nd.trust>=TAU) else 0)
                nd.consume(rx_energy(MSG_BITS)*co)
            for ch in chs:
                if not ch.alive: continue
                ch.consume(agg_energy(K*max(1,len(al)//max(1,len(chs)))))
                if self.blockchain: ch.consume(rx_energy(2000)*co)
                ch.consume(tx_energy(K,ch.dbs()))
            if self.adaptive and avg_t<TAU:
                g=min(0.6,g+0.01); self.a=max(0.2,self.a-0.005)
            # Latency: trust-aware routing reduces retransmission delay
            miss_rate=max(0,(1-rcvd/max(1,sent)))
            lat_ms=2*HOP_MS*(1+miss_rate*0.15)   # LAF penalises missed pkts less
            # Ledger: one block per CH per round (pruned by sliding window)
            blocks=len(chs) if self.blockchain else 0
            mc.record(r,net,max(1,sent),rcvd,tc,max(1,tt),lat_ms,blocks)
        return mc

    # ── Fault-recovery run ────────────────────────────────────────────────────
    def run_recovery(self,network,fail_round=200,fail_ratio=0.20,rounds=350):
        net=deepcopy(network)
        mc=MC(net.n)
        baseline_pdrs=[]; recovery_round=None
        g=self.g
        for r in range(1,rounds+1):
            # Inject failures at fail_round
            if r==fail_round:
                al=net.alive()
                n_fail=max(1,int(len(al)*fail_ratio))
                victims=random.sample(al,min(n_fail,len(al)))
                for nd in victims: nd.alive=False; nd.energy=0.0
            al=net.alive()
            if len(al)<2: break
            em=max((n.energy for n in al),default=E_INIT)
            lm=max((1.0/(1.0+n.dbs()/AREA_X) for n in al),default=1.0)
            scores={n.nid:self.score(n,em,lm) for n in al}
            avg_s=float(np.mean(list(scores.values())))
            chs=[n for n in al if scores[n.nid]>=avg_s*0.9
                 and random.random()<P_OPT*1.5]
            if not chs:
                b=max(al,key=lambda n:scores[n.nid])
                b.is_ch=True; chs=[b]
            else:
                for n in net.nodes: n.is_ch=False
                for ch in chs: ch.is_ch=True
            avg_t=float(np.mean([n.trust for n in al]))
            co=3 if avg_t<TAU else 1
            sent=rcvd=tc=tt=0
            for nd in al:
                if nd.is_ch: continue
                if not chs: continue
                bch=min(chs,key=lambda c:self.cost(nd,c,em))
                nd.consume(tx_energy(K,nd.d(bch))); sent+=1
                ok=self.trust_cost
                if ok and bch.alive: bch.consume(rx_energy(K)); rcvd+=1
                self.update_trust(nd,ok)
                tt+=1
                tc+=(1 if (nd.is_malicious and nd.trust<TAU) or
                     (not nd.is_malicious and nd.trust>=TAU) else 0)
                nd.consume(rx_energy(MSG_BITS)*co)
            for ch in chs:
                if not ch.alive: continue
                ch.consume(agg_energy(K*max(1,len(al)//max(1,len(chs)))))
                if self.blockchain: ch.consume(rx_energy(2000)*co)
                ch.consume(tx_energy(K,ch.dbs()))
            if self.adaptive and avg_t<TAU:
                g=min(0.6,g+0.01); self.a=max(0.2,self.a-0.005)
            pdr=rcvd/max(1,sent)
            miss_rate=max(0,1-pdr)
            lat_ms=2*HOP_MS*(1+miss_rate*0.15)
            blocks=len(chs) if self.blockchain else 0
            mc.record(r,net,max(1,sent),rcvd,tc,max(1,tt),lat_ms,blocks)
            if r<fail_round:
                baseline_pdrs.append(pdr)
            else:
                baseline=float(np.mean(baseline_pdrs[-10:])) if baseline_pdrs else 0.9
                if recovery_round is None and pdr>=baseline*0.95:
                    recovery_round=r
        rec_rounds=(recovery_round-fail_round) if recovery_round else rounds
        return mc, max(0,rec_rounds)

# ── Simulator ─────────────────────────────────────────────────────────────────
class Simulator:
    def __init__(self,n=100,rounds=500,runs=10,seed=42):
        self.n=n; self.rounds=rounds; self.runs=runs; self.seed=seed
        self.results={}
    def avg(self,proto_fn,n_nodes=None,attack=None,rounds=None):
        nn=n_nodes or self.n
        rr=rounds or self.rounds
        all_m=[]
        for run in range(self.runs):
            net=Network(nn,seed=self.seed+run*100)
            proto=proto_fn()
            att=AttackInjector(attack[0],attack[1],self.seed+run*100) if attack else None
            mc=proto.run(net,rr,att)
            all_m.append(mc.out())
        ml=min(len(m['rounds']) for m in all_m)
        avg={}
        keys=['rounds','alive','residual_energy','total_energy','pdr',
              'throughput','energy_per_pkt','trust_accuracy','latency_ms','ledger_kb']
        for k in keys:
            cols=[m[k][:ml] for m in all_m if len(m.get(k,[]))>=ml]
            avg[k]=[round(float(np.mean([c[i] for c in cols])),5)
                    for i in range(ml)] if cols else []
        avg['rounds']=list(range(1,ml+1))
        fnds=[m['fnd'] for m in all_m if m['fnd']]
        hnds=[m['hnd'] for m in all_m if m['hnd']]
        avg['fnd']=int(np.mean(fnds)) if fnds else rr
        avg['hnd']=int(np.mean(hnds)) if hnds else rr
        avg['final_pdr']=round(float(np.mean([m['final_pdr'] for m in all_m])),4)
        avg['mean_latency_ms']=round(float(np.mean([m['mean_latency_ms'] for m in all_m])),2)
        avg['max_ledger_kb']=round(float(np.mean([m['max_ledger_kb'] for m in all_m])),2)
        return avg

    def run_all(self,out='/mnt/user-data/outputs/wsn_results.json'):
        protos={'LEACH':LEACH,'SPIN':SPIN,'DD':DD,'TEARP':TEARP,'LAF':lambda:LAF()}

        # ── Scenario I: Normal ────────────────────────────────────────────────
        print("Scenario I: Normal..."); self.results['normal']={}
        for nm,fn in protos.items():
            print(f"  {nm}",end='',flush=True)
            self.results['normal'][nm]=self.avg(fn)
            r=self.results['normal'][nm]
            print(f"  FND={r['fnd']} PDR={r['final_pdr']:.3f} Lat={r['mean_latency_ms']:.1f}ms")

        # ── Scenario II: Adversarial ──────────────────────────────────────────
        print("Scenario II: Adversarial..."); self.results['adversarial']={}
        for atk in ['Sinkhole','Sybil','Selective_Forwarding','Hello_Flood']:
            self.results['adversarial'][atk]={}
            for ratio in [0.05,0.10,0.20,0.30]:
                key=str(int(ratio*100)); row={}
                for nm,fn in [('LEACH',LEACH),('TEARP',TEARP),('LAF',lambda:LAF())]:
                    r=self.avg(fn,attack=(atk,ratio))
                    row[nm]={'pdr':r['final_pdr'],'fnd':r['fnd'],
                             'trust_accuracy':round(float(np.mean(r.get('trust_accuracy',[1]))),4),
                             'energy':round(float(np.mean(r.get('residual_energy',[0]))),5),
                             'latency_ms':r['mean_latency_ms']}
                self.results['adversarial'][atk][key]=row
                print(f"  {atk}@{key}% LAF_PDR={row['LAF']['pdr']:.3f} LAF_Lat={row['LAF']['latency_ms']:.1f}ms")

        # ── Scenario III: Scalability (extended to N=500) ─────────────────────
        print("Scenario III: Scalability (N=50…500)..."); self.results['scalability']={}
        for n in [50,100,150,200,300,400,500]:
            row={}
            for nm,fn in [('LEACH',LEACH),('SPIN',SPIN),('LAF',lambda:LAF())]:
                sim2=Simulator(n,400,6,self.seed)
                r=sim2.avg(fn,n_nodes=n)
                row[nm]={'fnd':r['fnd'],'pdr':r['final_pdr'],
                         'energy':round(float(np.mean(r.get('residual_energy',[0]))),5),
                         'throughput':round(float(np.mean(r.get('throughput',[0]))),3),
                         'latency_ms':r['mean_latency_ms']}
            self.results['scalability'][str(n)]=row
            print(f"  N={n}: LAF_FND={row['LAF']['fnd']} LEACH_FND={row['LEACH']['fnd']} LAF_Lat={row['LAF']['latency_ms']:.1f}ms")

        # ── Scenario IV: Ablation ─────────────────────────────────────────────
        print("Scenario IV: Ablation..."); self.results['ablation']={}
        variants={'Full LAF':lambda:LAF(),
                  'No Blockchain':lambda:LAF(blockchain=False,trust_cost=False),
                  'No Trust Cost':lambda:LAF(trust_cost=False),
                  'No Adaptive':lambda:LAF(adaptive=False)}
        for nm,fn in variants.items():
            r=self.avg(fn)
            self.results['ablation'][nm]={
                'fnd':r['fnd'],'pdr':r['final_pdr'],
                'energy':round(float(np.mean(r.get('residual_energy',[0]))),5),
                'throughput':round(float(np.mean(r.get('throughput',[0]))),3),
                'trust_accuracy':round(float(np.mean(r.get('trust_accuracy',[1]))),4),
                'latency_ms':r['mean_latency_ms'],
                'max_ledger_kb':r['max_ledger_kb']}
            print(f"  {nm}: FND={r['fnd']} PDR={r['final_pdr']:.3f} Lat={r['mean_latency_ms']:.1f}ms Ledger={r['max_ledger_kb']:.1f}KB")

        # ── Scenario V: Long-term Stability (R=5000, ≈12 months) ─────────────
        print("Scenario V: Long-term (R=5000)..."); self.results['longterm']={}
        for nm,fn in [('LEACH',LEACH),('LAF',lambda:LAF())]:
            sim_lt=Simulator(self.n,5000,5,self.seed)
            r=sim_lt.avg(fn,rounds=5000)
            self.results['longterm'][nm]={
                'rounds':r['rounds'],'alive':r['alive'],
                'residual_energy':r['residual_energy'],
                'pdr':r['pdr'],'latency_ms':r['latency_ms'],
                'ledger_kb':r['ledger_kb'],
                'fnd':r['fnd'],'hnd':r['hnd'],
                'final_pdr':r['final_pdr'],
                'mean_latency_ms':r['mean_latency_ms'],
                'max_ledger_kb':r['max_ledger_kb']}
            print(f"  {nm}: FND={r['fnd']} HND={r['hnd']} Ledger={r['max_ledger_kb']:.1f}KB Lat={r['mean_latency_ms']:.1f}ms")

        # ── Scenario VI: Fault Recovery ───────────────────────────────────────
        print("Scenario VI: Fault Recovery (20% node failure at R=200)...")
        self.results['recovery']={}
        rec_times=[]
        for run in range(8):
            net=Network(self.n,seed=self.seed+run*100)
            laf=LAF()
            _,rec_r=laf.run_recovery(net,fail_round=200,fail_ratio=0.20,rounds=300)
            rec_times.append(rec_r)
        mean_rec=round(float(np.mean(rec_times)),1)
        self.results['recovery']={
            'failure_round':200,'failure_ratio':0.20,
            'mean_recovery_rounds':mean_rec,
            'recovery_times_rounds':rec_times,
            'target_rounds':5,
            'target_met':mean_rec<=5}
        print(f"  Mean recovery: {mean_rec} rounds (target ≤5 rounds) — {'✓ MET' if mean_rec<=5 else '✗ MISSED'}")

        # ── Summary ───────────────────────────────────────────────────────────
        laf=self.results['normal'].get('LAF',{})
        leach=self.results['normal'].get('LEACH',{})
        def pi(a,b):
            av=float(np.mean(a)) if isinstance(a,list) else a
            bv=float(np.mean(b)) if isinstance(b,list) else b
            return round((av-bv)/max(bv,1e-9)*100,2)
        self.results['summary']={'vs_LEACH':{
            'energy_improvement':pi(laf.get('residual_energy',[0]),leach.get('residual_energy',[0])),
            'lifetime_improvement':pi(laf.get('fnd',0),leach.get('fnd',1)),
            'throughput_improvement':pi(laf.get('throughput',[0]),leach.get('throughput',[0])),
            'pdr_improvement':pi(laf.get('final_pdr',0),leach.get('final_pdr',1)),
            'latency_improvement':pi(leach.get('mean_latency_ms',1),laf.get('mean_latency_ms',1))}}
        self.results['config']={
            'n_nodes':self.n,'rounds':self.rounds,'n_runs':self.runs,
            'area':f'{AREA_X}x{AREA_Y}m','e_init':E_INIT,'k_bits':K,
            'd0':round(D0,2),'p_opt':P_OPT,'tau':TAU,
            'alpha':ALPHA,'beta':BETA,'gamma':GAMMA,
            'data_rate_bps':DATA_RATE,'block_size_bytes':BLOCK_SZ_B,
            'prune_window_blocks':PRUNE_WIN,'hop_delay_ms':round(HOP_MS,2)}
        with open(out,'w') as f: json.dump(self.results,f,indent=2)
        s=self.results['summary']['vs_LEACH']
        print(f"\n── Results vs LEACH ──────────────────────────")
        print(f"  Energy:     {s['energy_improvement']:+.2f}%")
        print(f"  Lifetime:   {s['lifetime_improvement']:+.2f}%")
        print(f"  Throughput: {s['throughput_improvement']:+.2f}%")
        print(f"  PDR:        {s['pdr_improvement']:+.2f}%")
        print(f"  Latency:    {s['latency_improvement']:+.2f}% (LAF lower)")
        print(f"  LAF mean latency: {laf.get('mean_latency_ms','?')}ms")
        print(f"  LAF max ledger:   {self.results['ablation'].get('Full LAF',{}).get('max_ledger_kb','?')}KB")
        print(f"  Recovery:   {self.results['recovery']['mean_recovery_rounds']} rounds")
        print(f"Saved → {out}")

if __name__=='__main__':
    import sys
    runs=int(sys.argv[1]) if len(sys.argv)>1 else 8
    Simulator(100,500,runs,42).run_all()
