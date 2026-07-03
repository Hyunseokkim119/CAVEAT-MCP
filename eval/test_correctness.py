"""Correctness sanity: legitimate ops succeed; every tamper is rejected."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from caveat import Issuer, ToolManifest, ToolDef, CaveatServer, CaveatClient, Capability

def env():
    sk=Ed25519PrivateKey.generate(); rk=os.urandom(32)
    tool=ToolDef("read_file",{"name":"read_file","desc":"read"},1)
    cap=Issuer("S1",rk).mint_root("cap",ToolManifest.create(tool.definition,1,sk))
    cap=cap.attenuate({"k":"tool","v":"read_file"}).attenuate({"k":"prefix","v":"/proj/"})
    return sk,rk,tool,cap

def test_legit():
    sk,rk,tool,cap=env(); srv=CaveatServer(tool,sk,rk); cli=CaveatClient(srv,cap,1)
    assert cli.invoke({"tool":"read_file","path":"/proj/a"})["ok"]

def test_delegation_confined():
    sk,rk,tool,cap=env(); srv=CaveatServer(tool,sk,rk)
    d=cap.delegate("C2","t1"); dc=CaveatClient(srv,d,1)
    assert dc.invoke({"tool":"read_file","path":"/proj/a","agent":"C2","task":"t1"})["ok"]
    assert not dc.invoke({"tool":"read_file","path":"/proj/a","agent":"EVE","task":"t1"})["ok"]

def test_tamper_rejected():
    sk,rk,tool,cap=env(); srv=CaveatServer(tool,sk,rk)
    t=Capability(cap.cap_id,cap.manifest_digest,cap.manifest_version,cap.caveats[:-1],cap.tag)
    assert not CaveatClient(srv,t,1).invoke({"tool":"read_file","path":"/proj/a"})["ok"]

def test_rugpull_detected():
    sk,rk,tool,cap=env(); srv=CaveatServer(tool,sk,rk); cli=CaveatClient(srv,cap,1)
    srv.rug_pull({"name":"read_file","desc":"evil"})
    assert not cli.invoke({"tool":"read_file","path":"/proj/a"})["ok"]

if __name__=="__main__":
    for f in [test_legit,test_delegation_confined,test_tamper_rejected,test_rugpull_detected]:
        f(); print("PASS", f.__name__)
    print("ALL CORRECTNESS TESTS PASSED")
