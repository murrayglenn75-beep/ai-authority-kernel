'use strict';
const fs=require('node:fs');
const file=process.argv[2];
if(!file) { console.error('Missing security gate report path'); process.exit(2); }
let report;
try { report=JSON.parse(fs.readFileSync(file,'utf8')); }
catch(e) { console.error('Gate report missing or invalid:',e.message); process.exit(2); }
if(!report || !['PASS','WARN','FAIL'].includes(report.status)) {
  console.error('Unknown/missing security gate decision; deny by default');
  process.exit(2);
}
console.log('Security gate:',report.status);
console.log('Reasons:',JSON.stringify(report.reasons||[]));
if(report.status==='FAIL') {console.error('Security gate BLOCKED');process.exit(1);}
if(report.status==='WARN') console.warn('Security warnings require manual review before merge');
