import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

const source = await readFile(new URL('../src/lib/snapshot.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
const { parseSnapshot, finiteNumber, ageSeconds, displayValue } = await import('data:text/javascript;base64,' + Buffer.from(compiled).toString('base64'))

function fixture() {
  return { runtime: { owner_token: 'unit-test-owner' }, memory: {}, system: {}, workload: {}, security: {}, network: {}, self_budget: {}, collectors: {} }
}

test('missing or malformed evidence is rejected', () => {
  for (const value of [null, [], {}, { runtime: {} }, { ...fixture(), collectors: { attacks: null } }]) {
    assert.throws(() => parseSnapshot(JSON.stringify(value)))
  }
})

test('unknown measurements remain unknown and measured zero survives', () => {
  const value = fixture()
  value.system.cpu_percent = null
  value.security.defender_enabled = null
  const parsed = parseSnapshot(JSON.stringify(value))
  assert.equal(parsed.system.cpu_percent, null)
  assert.equal(parsed.security.defender_enabled, null)
  for (const invalid of [null, undefined, '0', NaN, Infinity]) assert.equal(finiteNumber(invalid), null)
  assert.equal(finiteNumber(0), 0)
})

test('sample age rejects unknown and future times', () => {
  const now = Date.parse('2026-09-14T00:00:30Z')
  assert.equal(ageSeconds('2026-09-14T00:00:00Z', now), 30)
  for (const invalid of [null, '', 'invalid', '2026-09-14T00:01:00Z']) assert.equal(ageSeconds(invalid, now), null)
})

test('untrusted display values cannot become fabricated labels', () => {
  assert.equal(displayValue({ value: 'safe' }), 'Unavailable')
  assert.equal(displayValue(''), 'Unavailable')
  assert.equal(displayValue('partial'), 'partial')
})
