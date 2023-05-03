from pox.topology.topology import *
from pox.openflow.topology import *

from pox.misc.Dijkstras import *

class MyTopology:
    def __init__(self,topology):
        self.topology=topology
        self.switches=[]
        self.hosts=[]
        self.switchAdj=None
        self.hostAdj=None

    def getAllEntities(self):
        def recurse(entity,known):
            if entity in known:
                return set()
            known.add(entity)
            if isinstance(entity,OpenFlowSwitch):
                for key in entity.ports.keys():
                    known=known.union(recurse(entity.ports[key],known),known)
            if isinstance(entity,OpenFlowPort):
                for new_ent in entity.entities:
                    known=known.union(recurse(new_ent,known),known)
            if isinstance(entity,Topology):
                for key in entity._entities.keys():
                    known=known.union(recurse(entity._entities[key],known),known)
            return known
        return recurse(self.topology,set())

    def getSwitchAdjacency(self):
        if self.switchAdj!=None:
           return self.switchAdj 
        sws = self.topology.getEntitiesOfType(t=Switch)
        def swAdj(sw):
            ports=sw.ports.values()
            adj=set()
            for p in ports:
                adj=adj.union(p.entities)
            return adj
        self.switchAdj = {sw:swAdj(sw) for sw in sws}
        return self.switchAdj
    
    def getHostAdjacency(self):
        if self.hostAdj!=None:
            return self.hostAdj
        hosts = self.topology.getEntitiesOfType(t=Host)
        def hostAdj(host,swAdj):
            adj=set()
            for sw in swAdj.keys():
                if host in swAdj[sw]:
                    adj.add(sw)
            if not adj:
                raise Exception(f"Host {host} not connected") 
            return adj
        self.getSwitchAdjacency()
        self.hostAdj = {host:hostAdj(host,self.switchAdj) for host in hosts}
        return self.hostAdj
    
    def ospf_host_paths(self):
        entAdj = self.getSwitchAdjacency().copy()
        entAdj.update(self.getHostAdjacency())
        graph = {ent:{adj:1 for adj in entAdj[ent]} for ent in entAdj.keys()}
        apsp = all_pairs_shortest_paths(graph)
        hosts=self.topology.getEntitiesOfType(t=Host)
        hostPaths = {(src,dest):list(filter(lambda x:isinstance(x,Switch),apsp[src][dest])) for src in hosts for dest in hosts if src!=dest}
        return hostPaths

    def host_path_bandwidth(self):
        host2hostPath=self.ospf_host_paths()
        hosts=self.topology.getEntitiesOfType(t=Host)
        switches=self.topology.getEntitiesOfType(t=Switch)
        switchCap={sw:1 for sw in switches}
        switch2switchCap={(src,dest):1 for src in switches for dest in switches if src!=dest }
        tm = ThroughputModel(hosts,switches,host2hostPath,switchCap,switch2switchCap)
        return tm.host2hostBandwidth
        
class ThroughputModel:
    def __init__(self,hosts,switches,host2hostPath,switchCap,switch2switchCap):
        self.hosts=hosts # [String]
        self.switches=switches # [String]
        self.host2hostPath=host2hostPath # {(host,host):[switch]}
        self.switchCap=switchCap # {switch:Int}
        self.switch2switchCap=switch2switchCap # {(switch,switch):Int}
        self.host2hostBandwidth_ctor()
        
    # {(switch,switch):Int}
    def switch2switchUse_ctor(self):
        init={s2key:0 for s2key in self.switch2switchCap}
        for h2key in self.host2hostPath.keys():
            path=self.host2hostPath[h2key]
            for s2s in zip(path[1:],path[:-1]):
                if not s2s in init:
                    raise Exception("switch2switchCap missing "+str(s2s))
                else:
                    init[s2s]+=1
        self.switch2switchUse=init
        return init
    
    # {switch:Int}
    def switchUse_ctor(self):
        init={sKey:0 for sKey in self.switchCap}
        for h2key in self.host2hostPath.keys():
            for switch in self.host2hostPath[h2key]:
                if not switch in init:
                    raise Exception("switchCap missing "++switch)
                else:
                    init[switch]+=1
        self.switchUse=init
        return init
     
    # {(host,host):Float}
    def host2hostBandwidth_ctor(self):
        self.switch2switchUse_ctor()
        self.switchUse_ctor()
        s2s_pc=propCap(self.switch2switchCap,self.switch2switchUse)
        s_pc=propCap(self.switchCap,self.switchUse)
        init={}
        for h2key in self.host2hostPath.keys():
            path=self.host2hostPath[h2key]
            minPropCap=100
            for s2s in zip(path[1:],path[:-1]):
                if s2s_pc[s2s]<minPropCap:
                    minPropCap=s2s_pc[s2s]
            for s in path:
                if s_pc[s]<minPropCap:
                    minPropCap=s_pc[s]
            init[h2key]=minPropCap
        self.host2hostBandwidth=init
        return init
    
def propCap(cap,use):
    init={}
    for capKey in cap.keys():
        if not capKey in use:
            raiseException("use does not contain "++capKey)
        else:
            init[capKey]=cap[capKey]/(1 if use[capKey]==0 else use[capKey])
    return init

def makeSymH2H(host2host):
    host2host.update({(h2hkey[1],h2hkey[0]):list(reversed(host2host[h2hkey])) for h2hkey in host2host.keys()})
    return host2host

def makeSymS2S(switch2switch):
    switch2switch.update({(s2skey[1],s2skey[0]):switch2switch[s2skey] for s2skey in switch2switch.keys()})
    return switch2switch
