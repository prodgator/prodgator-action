import { describe, it, expect, vi } from 'vitest';
import { readInputs, audienceFor, DEFAULT_PRODGATOR_URL } from '../inputs';

// @actions/core 3 is ESM only, so its namespace cannot be spied on.
vi.mock('@actions/core', async (importOriginal) => ({ ...(await importOriginal<typeof import('@actions/core')>()), warning: vi.fn() }));

const getter = (values: Record<string, string>) => (name: string) => values[name] ?? '';

describe('readInputs', () => {
  it('defaults to the Prodgator production API', () => {
    const i = readInputs(() => '', {});
    expect(i.prodgatorUrl).toBe('https://api.prodgator.io');
    expect(i.audience).toBe('https://api.prodgator.io');
  });
  it('defaults to production, the job id and a derived audience', () => {
    const i = readInputs(getter({}), { GITHUB_JOB: 'test' });
    expect(i).toMatchObject({ prodgatorUrl: DEFAULT_PRODGATOR_URL, audience: 'https://api.prodgator.io', jobName: 'test', name: 'default', matrix: null, failOnError: false, junit: [], artifacts: [] });
  });
  it('blames by default and turns it off only for false', () => {
    expect(readInputs(getter({}), {}).blame).toBe(true);
    expect(readInputs(getter({ blame: 'true' }), {}).blame).toBe(true);
    expect(readInputs(getter({ blame: 'false' }), {}).blame).toBe(false);
    expect(readInputs(getter({ blame: ' FALSE ' }), {}).blame).toBe(false);
  });
  it('derives the audience from prodgator-url', () => {
    expect(readInputs(getter({ 'prodgator-url': 'https://api.prodgator.dev/' }), { GITHUB_JOB: 'j' }).audience).toBe('https://api.prodgator.dev');
    expect(audienceFor('https://api.prodgator.dev/x/y')).toBe('https://api.prodgator.dev');
  });
  it('refuses plain http except for localhost', () => {
    expect(() => readInputs(getter({ 'prodgator-url': 'http://api.example.com' }), { GITHUB_JOB: 'j' })).toThrow(/https/);
    expect(readInputs(getter({ 'prodgator-url': 'http://127.0.0.1:3000' }), { GITHUB_JOB: 'j' }).prodgatorUrl).toBe('http://127.0.0.1:3000');
  });
  it('reads prodgator-url and ignores the removed spindle-url input', () => {
    expect(readInputs(getter({ 'prodgator-url': 'https://api.prodgator.dev' }), {}).prodgatorUrl).toBe('https://api.prodgator.dev');
    expect(readInputs(getter({ 'spindle-url': 'https://b.example' }), {}).prodgatorUrl).toBe('https://api.prodgator.io');
  });
  it('flattens nested matrix values and splits glob lists', () => {
    const i = readInputs(getter({ matrix: '{"os":"linux","include":{"x":1}}', junit: 'a/*.xml, b/*.xml', artifacts: 'dist/**\ncoverage/**\n' }), { GITHUB_JOB: 'j' });
    expect(i.matrix).toEqual({ os: 'linux', include: '{"x":1}' });
    expect(i.junit).toEqual(['a/*.xml', 'b/*.xml']);
    expect(i.junitName).toBeNull();
    expect(readInputs(getter({ 'junit-name': ' unit ' }), {}).junitName).toBe('unit');
    expect(i.artifacts).toEqual(['dist/**', 'coverage/**']);
    expect(readInputs(getter({ matrix: '{}' }), { GITHUB_JOB: 'j' }).matrix).toBeNull();
  });
  it('reads fail-on-error strictly', () => {
    expect(readInputs(getter({ 'fail-on-error': 'true' }), { GITHUB_JOB: 'j' }).failOnError).toBe(true);
    expect(readInputs(getter({ 'fail-on-error': 'yes' }), { GITHUB_JOB: 'j' }).failOnError).toBe(false);
  });
});
