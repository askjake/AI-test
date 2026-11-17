#!/usr/bin/env node
"use strict";
// Real Chromium and the production dashboard script, on localhost. Planning is
// mocked; review/validation/create use the real in-process typed API bridge.
// Every target, authentication, cloud/model, and run endpoint is forbidden.
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http');
const path=require('node:path'),os=require('node:os'),{execFileSync}=require('node:child_process');
// Qualification supplies an explicit module path so sibling/global packages
// cannot shadow the reviewed Playwright installation.
const {chromium}=require(process.env.BUILDER_GATE_PLAYWRIGHT_MODULE || 'playwright');
const root=path.resolve(__dirname,'..');
const exe=process.env.PLAYWRIGHT_CHROMIUM_PATH || chromium.executablePath();
if(!fs.existsSync(exe)) {console.error('BLOCKED: set PLAYWRIGHT_CHROMIUM_PATH to installed Chromium.');process.exit(78);}
const python=process.env.BUILDER_GATE_PYTHON || 'python3';
const env={...process.env,PYTHONPATH:path.join(root,'src')};
const capabilities=JSON.parse(execFileSync(python,['-c','import json; from dashboard.builder_policy import TARGET_CAPABILITIES; print(json.dumps([x.model_dump(mode="json") for x in TARGET_CAPABILITIES]))'],{env,cwd:root}));
const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'builder-browser-gate-'));
const events=[],unexpected=[],errors=[];
const plan={display_name:'Monitor Layout',goal:'Inspect the existing desktop and verify both monitoring windows.',target_type_suggestion:'rdp',
  field_placeholders:[{field:'target.window',placeholder:'orchestrator-rdp-viewer'}],
  specifications:[{title:'GPU Monitor',goal:'Inspect GPU Monitor on the left physical monitor.',setup:'Observe the existing desktop without changing window state.',assertions:['The independently identified GPU Monitor is maximized on the left display.']},
    {title:'System Monitor',goal:'Inspect System Monitor on the right physical monitor.',setup:'Observe the existing desktop without changing window state.',assertions:['System Monitor displays detailed resource graphs on the right display.']}],
  manual_outline:['Procedure'],assumptions:['The selected protocol exposes the intended desktop.'],open_questions:['What identifies the expanded System Monitor view?'],
  risks:['A separate remote session may differ from the physical desktop.'],suggested_verification_plan:'Review the bounded evidence and explicitly choose a preflight or run.'};
const proposal={id:'proposal12345678',state:'ready',proposal:plan,accepted_sections:[],rejected_sections:[]};
const html=fs.readFileSync(path.join(root,'templates/dashboard/index.html'),'utf8').replace('\ninitializeAuthenticatedApp();','\n// Offline gate supplies an operator session without authentication.');
let browser,server,failRefinement=false,failVisual=false;
async function main(){
  server=http.createServer(async(req,res)=>{
    const pathname=new URL(req.url,'http://127.0.0.1').pathname;
    if(pathname==='/' || pathname==='/favicon.ico') {res.setHeader('Content-Type',pathname==='/'?'text/html':'image/x-icon');res.end(pathname==='/'?html:'');return;}
    let raw='';for await(const chunk of req)raw+=chunk;let body=raw?JSON.parse(raw):null;
    events.push({path:pathname,method:req.method,body});
    let status=200,result;
    if(pathname==='/api/v1/authoring/wizard/target-options') result={hosts:{'ssh-terminal':[],rdp:[],vnc:[]},password_references:['desktop.rdp.pw','desktop.vncpass','gateway.pw','jump.hosts'],capabilities};
    else if(pathname==='/api/v1/projects') result=[];
    else if(pathname==='/api/v1/authoring/wizard/context-preview') result={fingerprint:'a'.repeat(64),draft_revision:'b'.repeat(64),sources:[{kind:'operator-intent',selected:true},{kind:'wizard-draft',selected:true}]};
    else if(pathname==='/api/v1/authoring/wizard/plan-jobs' && failRefinement){await new Promise(r=>setTimeout(r,600));status=422;result={detail:'Fixture authoring request failed; retry available.'};}
    else if(pathname==='/api/v1/authoring/wizard/visual/jobs'){result=failVisual?{id:'visual12345678',state:'failed',error:'Fixture screenshot suggestion failed.'}:{id:'visual12345678',state:'completed',proposal:{application_cues:'Model-only cues must not silently replace your answers.',window_state:'GPU Monitor fills the left captured display; System Monitor shows detailed graphs.',evidence_strategy:'Both captured display regions.',regions:[{kind:'application',label:'GPU Monitor',x:.05,y:.1,width:.4,height:.7,cue:'GPU title and resource graphs are visible.',expected_state:'GPU window fills the left captured display.'},{kind:'application',label:'System Monitor',x:.55,y:.1,width:.4,height:.7,cue:'System Monitor title and CPU/memory graphs.',expected_state:'Detailed CPU and memory graphs on the right captured display.'}],uncertainties:['Confirm physical display mapping independently.']}};}
    else if(pathname==='/api/v1/authoring/wizard/plan-jobs' || pathname==='/api/v1/authoring/wizard/plan-jobs/job12345678') result={id:'job12345678',state:'completed',proposal:structuredClone(proposal)};
    else if(pathname==='/api/v1/authoring/wizard/proposals/proposal12345678/accept') result={...proposal,accepted_sections:body.sections};
    else if(['/api/v1/authoring/wizard/review','/api/v1/authoring/wizard/readiness','/api/v1/authoring/wizard/validate','/api/v1/projects/authoring'].includes(pathname)){
      const output=JSON.parse(execFileSync(python,[path.join(__dirname,'builder_completion_browser_api.py'),fixture],{cwd:root,env,input:JSON.stringify({path:pathname,body}),maxBuffer:2*1024*1024}));
      status=output.status;result=output.body;
    }else{unexpected.push(pathname);status=500;result={detail:'Forbidden/unmatched offline route'};}
    res.statusCode=status;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch({executablePath:exe,headless:true,args:['--no-sandbox','--disable-gpu']});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
  await page.route('**/*',route=>{if(new URL(route.request().url()).origin!==origin){unexpected.push('external-request');return route.abort();}return route.continue();});
  await page.goto(origin);
  assert.equal(await page.evaluate(() => wizardContainsSensitiveProse('Credentials are entered in the Login window. Wait for tom_gui; references are mul.pass and vnc.vncpass.')), false);
  assert.equal(await page.evaluate(() => wizardContainsSensitiveProse('Launch /home/cory.link/ToM and save screenshots.png.')), false);
  assert.equal(await page.evaluate(() => wizardContainsSensitiveProse('password=FIXTURE-ONLY')), true);
  console.log('PASS permissive outcome prose in the production browser guard');
  await page.evaluate(()=>{AUTH_SESSION={role:'operator',csrf_token:'offline-test'};openNewProjectDialog();});
  await page.locator('#wizard-intent').fill('password=DUMMY-NEVER-PERSIST');
  assert(!await page.evaluate(()=>JSON.stringify(localStorage).includes('DUMMY-NEVER-PERSIST')));
  await page.locator('#wizard-step1-continue').click();
  assert.equal(events.filter(e=>e.path.endsWith('/context-preview')).length,0);
  assert.match(await page.locator('#wizard-step1-generation-status').textContent(),/credential-like/);
  console.log('PASS raw-intent privacy and early secret refusal');

  await page.locator('#wizard-intent').fill('Inspect the existing desktop and verify GPU Monitor on the left display and System Monitor on the right display.');
  await page.locator('#wizard-step1-continue').click();
  await page.locator('#wizard-review-heading').waitFor();
  assert.equal(events.filter(e=>e.path.endsWith('/accept')).length,0);
  assert.equal(await page.evaluate(()=>authoringState.wizardStep),1);
  assert.equal(await page.evaluate(()=>collectProjectAuthoringDocument().enabled),false);
  assert.equal(await page.evaluate(()=>collectProjectAuthoringDocument().schedule),null);
  await page.getByRole('button',{name:'Confirm reviewed plan and continue'}).click();
  await page.waitForFunction(()=>document.getElementById('wizard-plan-review-status').dataset.state==='error');
  assert.match(await page.locator('#wizard-plan-review-status').textContent(),/Choose inspection|Identify the existing/);
  assert.equal(await page.locator('#wizard-review-mode').getAttribute('aria-invalid'),'true');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'wizard-plan-review-status');
  console.log('PASS questions prevent premature acceptance; accessible failure focus');

  await page.locator('#wizard-review-mode').focus();await page.keyboard.press('ArrowDown');await page.keyboard.press('Tab');
  await page.locator('#wizard-review-session_scope').selectOption('physical-console');
  await page.locator('#wizard-review-application_cues').fill('GPU Monitor and System Monitor titles with independently reviewed visible graph cues.');
  await page.locator('#wizard-review-window_state').fill('GPU Monitor maximized; System Monitor expanded showing CPU and memory graphs.');
  await page.locator('#wizard-review-evidence_strategy').fill('One screenshot spans both displays, with left and right geometry independently reviewed.');
  await page.locator('#wizard-review-answer-0').fill('CPU and memory graphs are visible in the expanded resource view.');
  failRefinement=true;
  await page.locator('#wizard-plan-refine').click();
  assert.equal(await page.locator('#wizard-plan-refine').isDisabled(),true);
  assert.equal(await page.locator('#wizard-content').getAttribute('aria-busy'),'true');
  assert.match(await page.locator('#wizard-plan-review-status').textContent(),/context|Generating/);
  await page.waitForFunction(()=>!authoringState.wizardAutoGenerating);
  assert.match(await page.locator('#wizard-plan-review-status').textContent(),/Fixture authoring request failed/);
  assert.equal(await page.locator('#wizard-plan-refine').isDisabled(),false);
  assert.equal(await page.locator('#wizard-review-answer-0').inputValue(),'CPU and memory graphs are visible in the expanded resource view.');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'wizard-plan-review-status');
  console.log('PASS Refine visible busy/error/retry and retained answers');
  failRefinement=false;
  await page.getByRole('button',{name:'Refine provisional plan with these answers'}).click();
  await page.waitForFunction(()=>!authoringState.wizardAutoGenerating);
  const refine=events.filter(e=>e.path.endsWith('/plan-jobs')).at(-1);
  assert.equal(refine.body.draft.operator_decisions.mode,'audit');
  assert(!JSON.stringify(refine.body).includes('password_file'));
  await page.getByRole('button',{name:'Confirm reviewed plan and continue'}).click();
  await page.waitForFunction(()=>authoringState.wizardStep===2);
  assert.equal(events.filter(e=>e.path.endsWith('/accept')).length,1);
  assert.equal(await page.evaluate(()=>document.activeElement.id),'pa-target-type');
  assert.equal(await page.locator('#pa-connection-path option[value="ssh-jump"]').isDisabled(),true);
  await page.evaluate(()=>{const select=document.getElementById('pa-connection-path');select.value='ssh-jump';select.dispatchEvent(new Event('change',{bubbles:true}));});
  assert.equal(await page.locator('#pa-connection-path').inputValue(),'direct');
  console.log('PASS explicit refinement uses outcome answers; RDP jump blocked at selection');

  await page.locator('#pa-target-type').selectOption('vnc');
  assert.equal(await page.locator('#pa-connection-path option[value="ssh-jump"]').isDisabled(),false);
  await page.locator('#pa-connection-path').selectOption('ssh-jump');
  await page.locator('#pa-jump-host').fill('192.0.2.47');
  await page.getByRole('button',{name:'Allow this jump host in SSH allowlist'}).click();
  assert.match(await page.locator('#pa-ssh-allowlist').inputValue(),/192\.0\.2\.47/);
  assert(!await page.locator('#pa-vnc-allowlist').inputValue());
  console.log('PASS distinct visible jump-host allowlist decision');

  // Restore a reviewed direct target; these typed fields are fixture values only.
  await page.evaluate(()=>{const p=collectProjectAuthoringDocument();p.target={type:'rdp',host:'192.0.2.35',user:'fixture',window:'orchestrator-rdp-viewer',password_file:'desktop.rdp.pw',certificate_name:'desktop.example.invalid',certificate_fingerprint:'sha256:'+'a'.repeat(64),route:{type:'direct'}};p.rdp_host_allowlist=['192.0.2.35'];p.enabled=false;p.schedule=null;authoringState.projectDraft=p;fillProjectAuthoringForm(p);});
  await page.locator('#pa-rdp-certificate-fingerprint').fill('');
  await page.evaluate(()=>validateNewProjectAuthoring(collectProjectAuthoringDocument()));
  assert.equal(await page.locator('#pa-rdp-certificate-fingerprint').getAttribute('aria-invalid'),'true',await page.locator('#authoring-status').textContent());
  assert.equal(await page.locator('#pa-rdp-host').inputValue(),'192.0.2.35');
  assert.equal(events.filter(e=>e.path.includes('/target-probes')).length,0);
  console.log('PASS field-specific failed validation retains typed draft without target contact');

  await page.locator('#pa-rdp-certificate-fingerprint').fill('sha256:'+'a'.repeat(64));
  await page.locator('#pa-trust-source').fill('Independent fixture console record reviewed by the operator.');
  await page.locator('#pa-trust-confirm').check();
  await page.evaluate(()=>renderWizardStep(3));
  await page.locator('#sa-goal').fill('Inspect the existing physical desktop GPU Monitor on the left display.');
  await page.evaluate(()=>wizardGoStep(4));
  assert.equal(await page.evaluate(()=>authoringState.wizardStep),1);
  assert.match(await page.locator('#wizard-plan-review-status').textContent(),/Review and confirm this exact plan/);
  await page.getByRole('button',{name:'Confirm reviewed plan and continue'}).click();
  await page.waitForFunction(()=>authoringState.wizardStep===2);
  await page.evaluate(()=>validateNewProjectAuthoring(collectProjectAuthoringDocument()));
  assert.equal(await page.evaluate(()=>createValidationMatchesCurrent()),true);
  await page.evaluate(()=>createNewAuthoringProject());
  await page.waitForFunction(()=>authoringState.wizardCreatedSpecs.length===2);
  const create=events.find(e=>e.path==='/api/v1/projects/authoring');
  assert.equal(create.body.additional_specs.length,1);assert.equal(create.body.document.enabled,false);
  assert.equal(create.body.document.schedule,null);
  assert.match(create.body.manual_template,/Independent fixture console record reviewed by the operator/);
  assert.equal(await page.evaluate(()=>authoringState.wizardStep),6);
  await page.getByRole('heading',{name:'Project created through typed authoring'}).waitFor();
  assert(!events.some(e=>/\/authoring\/specs$/.test(e.path)));
  assert(!events.some(e=>e.path.includes('/trigger')));
  console.log('PASS stale-plan gate and complete disabled creation through real typed APIs');

  // Synthetic pixels only. No remote capture, cloud or active host access.
  await page.evaluate(()=>openWizardPlanReview());
  const originalCues=await page.locator('#wizard-review-application_cues').inputValue();
  const png=await page.evaluate(()=>{const c=document.createElement('canvas');c.width=640;c.height=320;const ctx=c.getContext('2d');ctx.fillStyle='#426588';ctx.fillRect(0,0,640,320);ctx.fillStyle='#c79855';ctx.fillRect(320,0,320,320);return c.toDataURL('image/png').split(',')[1];});
  await page.locator('#wizard-visual-file').setInputFiles({name:'synthetic.png',mimeType:'image/png',buffer:Buffer.from(png,'base64')});
  await page.waitForFunction(()=>Boolean(wizardVisual.image));
  assert.equal(events.filter(e=>e.path.endsWith('/visual/jobs')).length,0);
  assert(!await page.evaluate(data=>JSON.stringify(localStorage).includes(data),png));
  assert.match(await page.locator('#wizard-help-application_cues').textContent(),/Example:/);
  await page.locator('#wizard-visual-suggest').click();
  assert.match(await page.locator('#wizard-visual-status').textContent(),/approve the displayed/);
  assert.equal(events.filter(e=>e.path.endsWith('/visual/jobs')).length,0);
  async function draw(tool,start,end){
    await page.locator('#wizard-visual-tool').selectOption(tool);
    const canvas=page.locator('#wizard-visual-canvas');await canvas.scrollIntoViewIfNeeded();
    const b=await canvas.boundingBox();
    await page.mouse.move(b.x+b.width*start[0],b.y+b.height*start[1]);await page.mouse.down();
    await page.mouse.move(b.x+b.width*end[0],b.y+b.height*end[1],{steps:5});await page.mouse.up();
  }
  await draw('application',[.05,.15],[.45,.85]);
  assert.equal(await page.evaluate(()=>wizardVisual.regions.length),1);
  await page.locator('#wv-label-0').fill('GPU Monitor');
  await page.locator('#wv-cue-0').fill('GPU title and resource graphs.');
  await draw('mask',[.01,.01],[.09,.09]);
  assert.equal(await page.evaluate(()=>wizardVisual.masks.length),1);
  assert.deepEqual(await page.evaluate(()=>Array.from(wizardRedactedCanvas().getContext('2d').getImageData(20,20,1,1).data)),[0,0,0,255]);
  await page.locator('#wizard-visual-privacy').check();
  failVisual=true;
  await page.locator('#wizard-visual-suggest').click();
  await page.waitForFunction(()=>!wizardVisual.busy);
  assert.match(await page.locator('#wizard-visual-status').textContent(),/Fixture screenshot suggestion failed/);
  assert.equal(await page.evaluate(()=>wizardVisual.regions[0].label),'GPU Monitor');
  failVisual=false;
  await page.locator('#wizard-visual-suggest').click();
  await page.waitForFunction(()=>Boolean(wizardVisual.proposal)&&!wizardVisual.busy);
  assert.equal(await page.locator('#wizard-review-application_cues').inputValue(),originalCues);
  const posted=events.filter(e=>e.path.endsWith('/visual/jobs')).at(-1).body;
  assert.equal(posted.privacy_reviewed,true);assert.notEqual(posted.png_base64,png);
  await page.getByRole('spinbutton',{name:'Region 1 x percent',exact:true}).fill('8');
  await page.getByRole('spinbutton',{name:'Region 1 x percent',exact:true}).press('Tab');
  assert.equal(await page.evaluate(()=>wizardVisual.regions[0].x),.08);
  await draw('edit',[.2,.3],[.25,.35]);
  assert(Math.abs(await page.evaluate(()=>wizardVisual.regions[0].x)-.13)<.015);
  const width=await page.evaluate(()=>wizardVisual.regions[0].width);
  const corner=await page.evaluate(()=>{const r=wizardVisual.regions[0];return [r.x+r.width-.002,r.y+r.height-.002];});
  await draw('edit',corner,[corner[0]+.04,corner[1]+.04]);
  assert(await page.evaluate(()=>wizardVisual.regions[0].width)>width+.02);
  await page.getByRole('button',{name:'Mark left / right halves',exact:true}).click();
  const scope=await page.locator('#wizard-review-session_scope').inputValue();
  await page.locator('#wizard-visual-fill').click();
  assert.match(await page.locator('#wizard-review-application_cues').inputValue(),/GPU Monitor.*captured area/);
  assert.match(await page.locator('#wizard-review-evidence_strategy').inputValue(),/physical display mapping/);
  assert.equal(await page.locator('#wizard-review-session_scope').inputValue(),scope);
  assert.equal(await page.evaluate(()=>authoringState.wizardReview.reviewed_revision),null);
  assert.equal(await page.evaluate(()=>authoringState.wizardReview.answers.at(-1)),'');
  assert(!await page.evaluate(data=>JSON.stringify(localStorage).includes(data),png));
  await page.getByRole('button',{name:'Mark not applicable for refinement'}).last().click();
  assert.match(await page.evaluate(()=>authoringState.wizardReview.answers.at(-1)),/Not applicable.*refined plan/);
  await page.evaluate(()=>{
    window.syntheticCaptureStops=0;
    const c=document.createElement('canvas');c.width=640;c.height=320;c.getContext('2d').fillRect(0,0,640,320);
    const stream=c.captureStream(10);const track=stream.getVideoTracks()[0],stop=track.stop.bind(track);
    track.stop=()=>{syntheticCaptureStops++;stop();};
    Object.defineProperty(navigator.mediaDevices,'getDisplayMedia',{configurable:true,value:async()=>stream});
    window.syntheticCaptureCanvas=c;
  });
  const beforeCaptureJobs=events.filter(e=>e.path.endsWith('/visual/jobs')).length;
  await page.getByRole('button',{name:'Capture an open window',exact:true}).click();
  await page.waitForFunction(()=>wizardVisual.source==='Browser-selected window snapshot');
  await page.waitForFunction(()=>syntheticCaptureStops===1);
  assert.equal(events.filter(e=>e.path.endsWith('/visual/jobs')).length,beforeCaptureJobs);
  assert.equal(await page.locator('#wizard-visual-privacy').isChecked(),false);
  await page.evaluate(()=>closeEditor(true));
  assert.equal(await page.evaluate(()=>wizardVisual.image),null);
  console.log('PASS local image, explicit model consent, redacted pixels, editable regions, reviewed fill and ephemeral close');

  await page.evaluate(()=>{const p=defaultProjectDocument();p.enabled=true;p.schedule='0 3 * * *';localStorage.setItem(WIZARD_DRAFT_KEY,JSON.stringify({version:1,intent:'passwords for both are DUMMY-LEGACY',goal:'Inspect both monitoring windows.',project:p,planned_specs:[],step:1}));closeEditor(true);openNewProjectDialog();});
  assert(!await page.evaluate(()=>JSON.stringify(localStorage).includes('DUMMY-LEGACY')));
  assert.equal(await page.evaluate(()=>authoringState.wizardIntent),'');
  assert.equal(await page.evaluate(()=>collectProjectAuthoringDocument().enabled),false);
  assert.equal(await page.evaluate(()=>collectProjectAuthoringDocument().schedule),null);
  console.log('PASS legacy raw-intent purge and disabled unscheduled draft migration');
  assert.deepEqual(unexpected,[]);assert.deepEqual(errors,[]);
  console.log('BUILDER_COMPLETION_BROWSER_GATE=PASS');
}
main().catch(e=>{console.error(e.stack);process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));fs.rmSync(fixture,{recursive:true,force:true});});
