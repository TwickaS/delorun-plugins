#!/usr/bin/env node
// Validates every catalogue entry and the revocation list against their schemas, and checks that
// each entry's file name is its package name. Usage: node scripts/validate-entries.mjs [root]
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { validate } from './lib/schema.mjs'

const here = fileURLToPath(new URL('.', import.meta.url))
const DEFAULT_ROOT = resolve(here, '..')

/** The file name an entry for `packageName` must have: "@scope/name" becomes "@scope__name.yml". */
export function entryFileName(packageName) {
  return `${packageName.replace('/', '__')}.yml`
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function readYaml(path) {
  try {
    return { value: parse(readFileSync(path, 'utf8')) }
  } catch (error) {
    return { error: `is not valid YAML: ${error.message.split('\n')[0]}` }
  }
}

export function loadSchemas(root = DEFAULT_ROOT) {
  const dir = join(root, 'catalogue')
  return {
    'entry.schema.json': readJson(join(dir, 'entry.schema.json')),
    'revocations.schema.json': readJson(join(dir, 'revocations.schema.json')),
  }
}

/** Check one entry's contents and file name. Returns messages, empty when valid. */
export function validateEntry(value, fileName, schemas) {
  const errors = validate(value, schemas['entry.schema.json'], schemas)
  if (value !== null && typeof value === 'object' && typeof value.package === 'string') {
    const expected = entryFileName(value.package)
    if (fileName !== expected) errors.push(`file name: must be ${expected} for the package ${value.package}`)
  }
  if (Array.isArray(value?.versions)) {
    const versions = value.versions.map((item) => item?.version).filter((item) => typeof item === 'string')
    for (const version of new Set(versions.filter((item, index) => versions.indexOf(item) !== index))) {
      errors.push(`versions: ${version} is listed more than once`)
    }
    const ids = new Set()
    for (const [index, item] of value.versions.entries()) {
      for (const finding of Array.isArray(item?.findings) ? item.findings : []) {
        const id = finding?.id
        if (typeof id !== 'string') continue
        const key = `${item.version}/${id}`
        if (ids.has(key)) errors.push(`versions[${index}].findings: the id ${id} is used more than once`)
        ids.add(key)
      }
    }
  }
  return errors
}

/** Validate a whole checkout. Returns `{ errors, entries }`, with `errors` as "path: message" lines. */
export function validateRepository(root = DEFAULT_ROOT) {
  const errors = []
  const schemas = loadSchemas(root)
  const entriesDir = join(root, 'catalogue', 'entries')
  let entries = 0
  if (!existsSync(entriesDir)) {
    errors.push('catalogue/entries: the folder is missing')
  } else {
    for (const name of readdirSync(entriesDir).sort()) {
      if (name === '.gitkeep') continue
      const label = `catalogue/entries/${name}`
      if (!name.endsWith('.yml')) {
        errors.push(`${label}: entries are .yml files`)
        continue
      }
      entries += 1
      const { value, error } = readYaml(join(entriesDir, name))
      if (error) errors.push(`${label}: ${error}`)
      else for (const message of validateEntry(value, name, schemas)) errors.push(`${label}: ${message}`)
    }
  }
  const revocationsPath = join(root, 'catalogue', 'revocations.yml')
  if (!existsSync(revocationsPath)) {
    errors.push('catalogue/revocations.yml: the file is missing')
  } else {
    const { value, error } = readYaml(revocationsPath)
    if (error) errors.push(`catalogue/revocations.yml: ${error}`)
    else {
      for (const message of validate(value, schemas['revocations.schema.json'], schemas)) {
        errors.push(`catalogue/revocations.yml: ${message}`)
      }
    }
  }
  return { errors, entries }
}

if (process.argv[1] && basename(process.argv[1]) === 'validate-entries.mjs') {
  const { errors, entries } = validateRepository(process.argv[2] ? resolve(process.argv[2]) : DEFAULT_ROOT)
  if (errors.length > 0) {
    for (const line of errors) console.error(line)
    console.error(`${errors.length} problem${errors.length === 1 ? '' : 's'} found.`)
    process.exit(1)
  }
  console.log(`${entries} ${entries === 1 ? 'entry' : 'entries'} and revocations.yml are valid.`)
}
