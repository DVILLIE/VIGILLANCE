type Section = Record<string, unknown>
export interface Snapshot {
  runtime: Section; memory: Section; system: Section; workload: Section;
  security: Section; network: Section; self_budget: Section;
  collectors: Record<string, Section>;
}
function record(value: unknown): value is Section {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
export function parseSnapshot(text: string): Snapshot {
  const value: unknown = JSON.parse(text)
  if (!record(value) || !record(value.runtime) || typeof value.runtime.owner_token !== 'string') {
    throw new Error('This file is not a DVielle runtime snapshot.')
  }
  for (const key of ['runtime', 'memory', 'system', 'workload', 'security', 'network', 'self_budget', 'collectors']) {
    if (!record(value[key])) throw new Error('Snapshot section ' + key + ' is missing or invalid.')
  }
  if (Object.values(value.collectors as Section).some(collector => !record(collector))) {
    throw new Error('Snapshot collector entries are invalid.')
  }
  return value as unknown as Snapshot
}
export function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}
export function ageSeconds(value: unknown, now: number): number | null {
  if (typeof value !== 'string') return null
  const age = (now - Date.parse(value)) / 1000
  return Number.isFinite(age) && age >= 0 ? age : null
}
export function displayValue(value: unknown, fallback = 'Unavailable'): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback
}
