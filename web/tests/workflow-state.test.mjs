import test from 'node:test';
import assert from 'node:assert/strict';
import { queueRequest, readQueueParams, percentText, parseSBOM, safeListReturn, campaignTargetError } from '../src/workflow-state.ts';
test('queue request validates page/view and only forwards supported filters', () => {
  const url = new URL(queueRequest(new URLSearchParams('view=unknown&page=-4&size=17&q=CVE%20portal&group=abc&token=hidden')), 'http://hunter');
  assert.equal(url.searchParams.get('view'), 'all');
  assert.equal(url.searchParams.get('page'), '1');
  assert.equal(url.searchParams.get('size'), '25');
  assert.equal(url.searchParams.get('q'), 'CVE portal');
  assert.equal(url.searchParams.get('group'), 'abc');
  assert.equal(url.searchParams.has('token'), false);
  assert.equal(readQueueParams(new URLSearchParams('view=mine&page=3&size=50')).view, 'mine');
});
test('unknown threat scores remain unknown, zero is a real supplied value', () => {
  assert.equal(percentText(null), '미확인');
  assert.equal(percentText(undefined), '미확인');
  assert.equal(percentText(NaN), '미확인');
  assert.equal(percentText(0), '0%');
  assert.equal(percentText(0.1), '10%');
});
test('SBOM import checks supported document types without treating arbitrary JSON as inventory', () => {
  assert.equal(parseSBOM('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}').specVersion, '1.6');
  assert.equal(parseSBOM('{"spdxVersion":"SPDX-2.3","packages":[]}').spdxVersion, 'SPDX-2.3');
  for (const invalid of ['null', '[]', 'malformed', '{}', '{"bomFormat":"CycloneDX","specVersion":"1.2"}']) assert.throws(() => parseSBOM(invalid));
});
test('detail return accepts list filters but rejects external and nested destinations', () => {
  assert.equal(safeListReturn('/software?q=auth&page=3', '/software'), '/software?q=auth&page=3');
  assert.equal(safeListReturn('//evil.example', '/software'), '/software');
  assert.equal(safeListReturn('/software/other', '/software'), '/software');
  assert.equal(safeListReturn('/campaigns?q=release', '/campaigns'), '/campaigns?q=release');
  assert.equal(safeListReturn('/campaigns?x=\n', '/campaigns'), '/campaigns');
});
test('campaign target validation rejects incomplete, duplicate and oversized plans', () => {
  assert.ok(campaignTargetError([]));
  assert.ok(campaignTargetError([{ service_id:'a',profile:'authorization' }]));
  assert.ok(campaignTargetError([{ service_id:'a',profile:'shell' }]));
  assert.ok(campaignTargetError([{ service_id:'a',profile:'http-baseline' }, { service_id:'a',profile:'http-baseline' }]));
  assert.ok(campaignTargetError(Array.from({ length:21 }, (_, i) => ({ service_id:String(i),profile:'http-baseline' }))));
  assert.equal(campaignTargetError([{ service_id:'a',profile:'http-baseline' }, { service_id:'a',profile:'authorization',scenario_id:'scenario' }]), '');
});

test('changed campaign observations appear once without merging identical fingerprints across services', async () => {
  const { unchangedObservations } = await import('../src/workflow-state.ts');
  const before = [{ service_id: 'a', fingerprint: 'same' }, { service_id: 'b', fingerprint: 'same' }];
  assert.deepEqual(unchangedObservations(before, [{ after: before[0] }]), [before[1]]);
  assert.equal(before.length, 2);
});
