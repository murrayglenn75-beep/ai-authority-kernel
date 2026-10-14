'use strict';
const assert=require('node:assert/strict');
const cp=require('node:child_process');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const checker=path.resolve(__dirname,'../scripts/enforce-security-gate.cjs');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'security-gate-'));
try {
  for(const [report,expected] of [
    [{status:'PASS',reasons:[]},0],
    [{status:'WARN',reasons:['review']},0],
    [{status:'FAIL',reasons:['critical']},1],
    [{status:'UNKNOWN'},2],
    [{},2]
  ]) {
    const file=path.join(dir,'report.json');
    fs.writeFileSync(file,JSON.stringify(report));
    const r=cp.spawnSync(process.execPath,[checker,file],{encoding:'utf8'});
    assert.equal(r.status,expected,'report '+JSON.stringify(report));
  }
  const missing=cp.spawnSync(process.execPath,[checker,path.join(dir,'missing')]);
  assert.equal(missing.status,2);
  console.log('6/6 security gate enforcement checks passed');
} finally { fs.rmSync(dir,{recursive:true,force:true}); }
