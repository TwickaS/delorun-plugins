import assert from 'node:assert/strict'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { after, describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import { parse, stringify } from 'yaml'
import { entryFileName, validateRepository } from './validate-entries.mjs'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURE = 'delorun-plugin-example.yml'
const fixtureText = readFileSync(join(repo, 'scripts', 'fixtures', FIXTURE), 'utf8')
const temporary = []

/** A scratch checkout with the real schemas, the real revocations.yml and the given entry files. */
function makeRoot(files = {}) {
  const root = mkdtempSync(join(tmpdir(), 'delorun-plugins-'))
  temporary.push(root)
  mkdirSync(join(root, 'catalogue', 'entries'), { recursive: true })
  for (const name of ['entry.schema.json', 'revocations.schema.json', 'revocations.yml']) {
    cpSync(join(repo, 'catalogue', name), join(root, 'catalogue', name))
  }
  for (const [name, text] of Object.entries(files)) {
    writeFileSync(join(root, 'catalogue', 'entries', name), text)
  }
  return root
}

function entry(change) {
  const value = parse(fixtureText)
  change?.(value)
  return stringify(value)
}

after(() => {
  for (const root of temporary) rmSync(root, { recursive: true, force: true })
})

describe('entries', () => {
  it('passes a valid entry', () => {
    const { errors, entries } = validateRepository(makeRoot({ [FIXTURE]: fixtureText }))
    assert.deepEqual(errors, [])
    assert.equal(entries, 1)
  })

  it('passes an empty catalogue/entries folder', () => {
    assert.deepEqual(validateRepository(makeRoot()), { errors: [], entries: 0 })
  })

  it('passes the real repository', () => {
    assert.deepEqual(validateRepository(repo).errors, [])
  })

  it('fails an entry with a missing field', () => {
    for (const field of ['package', 'title', 'description', 'repository', 'license', 'author', 'versions']) {
      const text = entry((value) => {
        delete value[field]
      })
      const { errors } = validateRepository(makeRoot({ [FIXTURE]: text }))
      assert.ok(
        errors.some((line) => line.includes(`${field}: is required`)),
        `${field}: ${errors.join('; ')}`,
      )
    }
  })

  it('fails a version with a missing field', () => {
    const text = entry((value) => {
      delete value.versions[0].integrity
    })
    const { errors } = validateRepository(makeRoot({ [FIXTURE]: text }))
    assert.deepEqual(errors, ['catalogue/entries/delorun-plugin-example.yml: versions[0].integrity: is required'])
  })

  it('fails a file name that is not the package name', () => {
    const { errors } = validateRepository(makeRoot({ 'other-name.yml': fixtureText }))
    assert.equal(errors.length, 1)
    assert.match(errors[0], /file name: must be delorun-plugin-example\.yml/)
  })

  it('names the file of a scoped package with two underscores', () => {
    assert.equal(entryFileName('@scope/name'), '@scope__name.yml')
    const scoped = entry((value) => {
      value.package = '@scope/name'
    })
    assert.deepEqual(validateRepository(makeRoot({ '@scope__name.yml': scoped })).errors, [])
    assert.equal(validateRepository(makeRoot({ '@scope-name.yml': scoped })).errors.length, 1)
  })

  it('fails a bad integrity string', () => {
    for (const integrity of ['sha512-abc', 'sha1-LvPFs39Sx40Ft2AJ3BzEsP87jZWc4c5vn6nJLNyql1mpdPC71iet3DvsX9lNdiMSeRiRonqnSpClwEChJQbqrA==', '']) {
      const text = entry((value) => {
        value.versions[0].integrity = integrity
      })
      const { errors } = validateRepository(makeRoot({ [FIXTURE]: text }))
      assert.ok(
        errors.some((line) => line.includes('versions[0].integrity')),
        `${integrity}: ${errors.join('; ')}`,
      )
    }
  })

  it('fails a version that is a range, and one listed twice', () => {
    const range = entry((value) => {
      value.versions[0].version = '^1.2.0'
    })
    assert.ok(validateRepository(makeRoot({ [FIXTURE]: range })).errors.length > 0)
    const twice = entry((value) => {
      value.versions.push(structuredClone(value.versions[0]))
    })
    const { errors } = validateRepository(makeRoot({ [FIXTURE]: twice }))
    assert.ok(errors.some((line) => line.includes('1.2.0 is listed more than once')))
  })

  it('fails an unknown field, a non-HTTPS repository and over-long text', () => {
    const text = entry((value) => {
      value.addedBy = 7
      value.repository = 'http://example.com/plugin'
      value.title = 'x'.repeat(81)
    })
    const { errors } = validateRepository(makeRoot({ [FIXTURE]: text }))
    assert.equal(errors.length, 3, errors.join('; '))
  })

  it('checks a finding and a badge', () => {
    const bad = entry((value) => {
      value.versions[0].findings[0].severity = 'severe'
      value.versions[0].badges = [{ kind: 'tested-with-delorun' }]
    })
    const { errors } = validateRepository(makeRoot({ [FIXTURE]: bad }))
    assert.ok(errors.some((line) => line.includes('findings[0].severity')))
    assert.ok(errors.some((line) => line.includes('badges[0].delorun: is required')))
    const good = entry((value) => {
      value.versions[0].badges = [
        {
          kind: 'tested-with-delorun',
          delorun: '0.1.0',
          dsh: '0.2.2',
          channel: 'stable',
          result: 'passed',
          corpus: 'a'.repeat(40),
          run: 'https://example.com/run/1',
          recorded: '2026-01-15T10:00:00Z',
        },
      ]
    })
    assert.deepEqual(validateRepository(makeRoot({ [FIXTURE]: good })).errors, [])
  })

  it('fails text that is not YAML and files that are not .yml', () => {
    const { errors } = validateRepository(makeRoot({ 'broken.yml': 'package: [unclosed', 'notes.txt': 'x' }))
    assert.equal(errors.length, 2)
    assert.match(errors[0], /broken\.yml: is not valid YAML/)
    assert.match(errors[1], /notes\.txt: entries are \.yml files/)
  })
})

describe('revocations.yml', () => {
  const revocation = {
    package: 'delorun-plugin-example',
    versions: ['1.2.0'],
    reason: 'broken',
    message: 'Crashes the studio on start.',
    revoked: '2026-01-16T09:00:00Z',
  }

  function withRevocations(text) {
    const root = makeRoot()
    writeFileSync(join(root, 'catalogue', 'revocations.yml'), text)
    return validateRepository(root).errors
  }

  it('passes a valid revocation', () => {
    assert.deepEqual(withRevocations(stringify({ revocations: [revocation] })), [])
  })

  it('fails a bad reason and a missing field', () => {
    const errors = withRevocations(stringify({ revocations: [{ ...revocation, reason: 'rude', message: undefined }] }))
    assert.equal(errors.length, 2)
    assert.ok(errors.some((line) => line.includes('revocations[0].reason')))
    assert.ok(errors.some((line) => line.includes('revocations[0].message: is required')))
  })

  it('fails a missing file', () => {
    const root = makeRoot()
    rmSync(join(root, 'catalogue', 'revocations.yml'))
    assert.deepEqual(validateRepository(root).errors, ['catalogue/revocations.yml: the file is missing'])
  })
})
