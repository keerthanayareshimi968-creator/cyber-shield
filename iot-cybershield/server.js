import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const devices = [
  { id: 'IOT-001', name: 'Smart Camera', firmware: '2.1.0', minimum: '2.0.0', status: 'Secure' },
  { id: 'IOT-002', name: 'Smart Lock', firmware: '1.4.0', minimum: '1.3.0', status: 'Secure' },
  { id: 'IOT-003', name: 'Network Router', firmware: '1.2.0', minimum: '1.2.0', status: 'Review' },
  { id: 'IOT-004', name: 'Temperature Sensor', firmware: '3.0.0', minimum: '2.8.0', status: 'Secure' }
];
const events = [];
const seenRequestIds = new Set();
const started = Date.now();
const compareVersions = (a,b) => {
  const aa = String(a).split('.').map(n => parseInt(n,10)||0);
  const bb = String(b).split('.').map(n => parseInt(n,10)||0);
  for(let i=0;i<Math.max(aa.length,bb.length);i++){ const d=(aa[i]||0)-(bb[i]||0); if(d) return d; }
  return 0;
};
const addEvent = (deviceId, type, result, reason, severity='INFO') => {
  const event = { id: crypto.randomUUID(), time: new Date().toISOString(), deviceId, type, result, reason, severity };
  events.unshift(event); if(events.length>200) events.pop(); return event;
};
app.get('/api/health', (_req,res)=>res.json({ok:true, service:'IoT CyberShield API', mode:'software emulation'}));
app.get('/api/devices', (_req,res)=>res.json(devices));
app.get('/api/events', (_req,res)=>res.json(events));
app.get('/api/metrics', (_req,res)=>res.json({ devices:devices.length, verified:events.filter(e=>e.type==='Firmware verification'&&e.result==='PASSED').length, rejected:events.filter(e=>e.result==='BLOCKED'||e.result==='REJECTED').length, alerts:events.filter(e=>e.severity==='HIGH').length, uptimeSeconds:Math.floor((Date.now()-started)/1000) }));
app.post('/api/verify', (req,res)=>{
  const { deviceId, fileName, fileHash, trustedHash, firmwareVersion, requestId, signatureValid } = req.body || {};
  const device = devices.find(d=>d.id===deviceId);
  if(!device) return res.status(400).json({error:'Select a valid virtual device.'});
  if(!fileHash || !/^[a-f0-9]{64}$/i.test(fileHash)) return res.status(400).json({error:'A valid SHA-256 file hash is required.'});
  const checks = [];
  const integrity = trustedHash ? fileHash.toLowerCase()===trustedHash.toLowerCase() : null;
  checks.push({name:'SHA-256 integrity', status: integrity===null?'NOT_CONFIGURED':integrity?'PASSED':'FAILED', detail: integrity===null?'No trusted reference hash supplied. Hash was calculated, but integrity cannot be confirmed.':integrity?'File hash matches the trusted reference.':'File hash differs from the trusted reference.'});
  checks.push({name:'Signature verification', status: signatureValid===true?'PASSED':signatureValid===false?'FAILED':'NOT_CONFIGURED', detail:signatureValid===true?'Signature was verified by the configured verifier.':signatureValid===false?'Signature verification failed.':'No signature verifier result was supplied; this check was not performed.'});
  const versionOk = firmwareVersion ? compareVersions(firmwareVersion, device.minimum)>=0 : false;
  checks.push({name:'Minimum version policy',status:versionOk?'PASSED':'FAILED',detail:versionOk?`Firmware ${firmwareVersion} meets minimum ${device.minimum}.`:`Firmware ${firmwareVersion||'(missing)'} is below the minimum permitted version ${device.minimum}.`});
  const replay = !requestId || seenRequestIds.has(requestId);
  checks.push({name:'Replay protection',status:replay?'FAILED':'PASSED',detail:replay?'Missing or previously used request ID.':'Unique request ID accepted.'});
  if(requestId && !seenRequestIds.has(requestId)) seenRequestIds.add(requestId);
  const passed = checks.every(c=>c.status==='PASSED');
  const result = passed?'APPROVED':'REJECTED';
  const reason = passed?'All configured checks passed.':checks.filter(c=>c.status!=='PASSED').map(c=>`${c.name}: ${c.detail}`).join(' ');
  addEvent(deviceId,'Firmware verification',passed?'PASSED':'REJECTED',reason,passed?'INFO':'HIGH');
  res.json({deviceId,fileName:fileName||'firmware.bin',fileHash,checks,decision:result,reason,mode:'Software prototype; no device firmware was installed.'});
});
app.post('/api/simulate', (req,res)=>{
  const {deviceId, attackType} = req.body || {};
  const device = devices.find(d=>d.id===deviceId);
  if(!device) return res.status(400).json({error:'Select a valid virtual device.'});
  const definitions = {
    modification: {title:'Firmware modification', check:'SHA-256 integrity', result:'BLOCKED', reason:'The simulated firmware hash differs from the trusted reference hash.', defense:'Reject the package when the calculated hash does not match the trusted hash.'},
    injection: {title:'Malicious firmware injection', check:'Digital signature policy', result:'BLOCKED', reason:'The scenario supplies an invalid/untrusted signature result.', defense:'Require a valid signature from a trusted firmware signing key. This prototype demonstrates the policy outcome; it does not execute the file.'},
    replay: {title:'Replay attack', check:'Replay protection', result:'BLOCKED', reason:'The scenario reuses an update request ID that has already been processed.', defense:'Persist request IDs or nonces and reject duplicates.'},
    downgrade: {title:'Firmware downgrade', check:'Minimum version policy', result:'BLOCKED', reason:`The proposed old firmware is below the device minimum version ${device.minimum}.`, defense:'Enforce a monotonic version/counter policy before approving updates.'}
  };
  const d=definitions[attackType]; if(!d) return res.status(400).json({error:'Choose a supported attack scenario.'});
  const event=addEvent(deviceId,d.title,d.result,d.reason,'HIGH');
  res.json({deviceId,attackType,...d,event,steps:[
    {label:'Request received',status:'PASSED',detail:`Scenario prepared for ${device.name} (${device.id}).`},
    {label:d.check,status:'FAILED',detail:d.reason},
    {label:'Defense response',status:'PASSED',detail:d.defense},
    {label:'Final decision',status:'BLOCKED',detail:'Update rejected in the software simulation.'}
  ],disclaimer:'Controlled software simulation only. No real device was attacked and no uploaded firmware was executed.'});
});
app.post('/api/reset-demo', (_req,res)=>{events.length=0;seenRequestIds.clear();res.json({ok:true});});
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', ()=>console.log(`IoT CyberShield running on ${port}`));
