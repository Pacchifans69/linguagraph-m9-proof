#!/usr/bin/env python3
"""Fail-closed verifier for M9 targeted Vitest JSON evidence."""
import argparse, json, os, sys
FAIL="FAIL: "
def die(msg):
    sys.stderr.write(FAIL+msg+"\n"); raise SystemExit(1)
def load(path,label):
    try:
        with open(path,encoding="utf-8") as h: value=json.load(h)
    except Exception as exc:
        die("%s is missing or unparseable: %s"%(label,exc))
    if not isinstance(value,dict): die("%s must be a JSON object"%label)
    return value
def relfile(name,web_root):
    if not isinstance(name,str) or not name: die("testResults[].name is missing")
    root=os.path.realpath(web_root); absolute=os.path.realpath(name)
    try: rel=os.path.relpath(absolute,root)
    except ValueError: die("test file is outside web root: %r"%name)
    rel=rel.replace(os.sep,"/")
    if rel==".." or rel.startswith("../"): die("test file is outside web root: %r"%name)
    return rel
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--report",required=True); p.add_argument("--map",required=True,dest="map_path")
    p.add_argument("--web-root",required=True); p.add_argument("--expected-tests",required=True,type=int)
    p.add_argument("--json-out",required=True); a=p.parse_args()
    report=load(a.report,"Vitest report"); mapping=load(a.map_path,"semantic map")
    if mapping.get("schema")!="linguagraph-m9-targeted-test-map/v1": die("unexpected semantic-map schema")
    if mapping.get("expected_total")!=a.expected_tests: die("semantic-map expected_total mismatch")
    for key,want in (("numTotalTests",a.expected_tests),("numPassedTests",a.expected_tests),("numFailedTests",0),("numPendingTests",0)):
        got=report.get(key)
        if type(got) is not int or got!=want: die("%s is %r (expected %d)"%(key,got,want))
    if report.get("success") is not True: die("Vitest JSON success is not true")
    expected_files=mapping.get("files"); reqs=mapping.get("requirements")
    if not isinstance(expected_files,dict) or not expected_files: die("semantic-map files invalid")
    if not isinstance(reqs,dict) or len(reqs)!=33: die("semantic-map requirements must contain exactly 33 entries")
    counts={}; titles={}
    results=report.get("testResults")
    if not isinstance(results,list): die("testResults is not a list")
    for result in results:
        if not isinstance(result,dict): die("testResults entry is not an object")
        rel=relfile(result.get("name"),a.web_root); assertions=result.get("assertionResults")
        if not isinstance(assertions,list): die("assertionResults is not a list for %s"%rel)
        counts[rel]=counts.get(rel,0)+len(assertions)
        for assertion in assertions:
            if not isinstance(assertion,dict): die("assertion result is not an object")
            title=assertion.get("title"); status=assertion.get("status")
            if not isinstance(title,str) or not title: die("assertion title is missing")
            titles.setdefault(title,[]).append((rel,status))
            if status!="passed": die("targeted assertion did not pass: %s (%r)"%(title,status))
    if counts!=expected_files: die("targeted file/count set mismatch: got %r expected %r"%(counts,expected_files))
    for req,needed in reqs.items():
        if not isinstance(needed,list) or not needed: die("%s has no mapped titles"%req)
        for title in needed:
            records=titles.get(title,[])
            if len(records)!=1: die("%s title %r occurred %d times (expected 1)"%(req,title,len(records)))
    summary={"schema":"linguagraph-m9-targeted-vitest-verify/v1","expected_total":a.expected_tests,"files":counts,"requirement_count":len(reqs),"status":"PASS"}
    tmp=a.json_out+".tmp"
    with open(tmp,"w",encoding="utf-8") as h: json.dump(summary,h,indent=2,sort_keys=True); h.write("\n")
    os.replace(tmp,a.json_out)
    print("M9_TARGETED_VITEST_VERIFY=PASS tests=%d requirements=%d files=%d"%(a.expected_tests,len(reqs),len(counts)))
if __name__=="__main__": main()
