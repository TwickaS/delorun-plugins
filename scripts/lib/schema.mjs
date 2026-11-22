// A small JSON Schema checker for the keywords the catalogue schemas use. It exists so the
// repository needs no dependency besides a YAML parser. An unknown keyword throws, so a schema
// that uses something this file does not check cannot pass silently.

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', '$defs'])
const KEYWORDS = new Set([
  '$ref',
  'type',
  'enum',
  'const',
  'pattern',
  'minLength',
  'maxLength',
  'minimum',
  'minItems',
  'maxItems',
  'uniqueItems',
  'required',
  'properties',
  'additionalProperties',
  'items',
])

function typeOf(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (Number.isInteger(value)) return 'integer'
  return typeof value
}

function matchesType(value, type) {
  const actual = typeOf(value)
  return actual === type || (type === 'number' && actual === 'integer')
}

function show(value) {
  const text = JSON.stringify(value)
  return text === undefined ? String(value) : text.length > 60 ? `${text.slice(0, 57)}...` : text
}

function lookup(root, pointer) {
  let node = root
  for (const part of pointer.split('/').filter(Boolean)) {
    if (node === null || typeof node !== 'object' || !(part in node)) {
      throw new Error(`Schema reference not found: #/${pointer}`)
    }
    node = node[part]
  }
  return node
}

/**
 * Check `value` against `schema`. `schemas` maps a file name to a loaded schema, for references
 * such as "entry.schema.json#/$defs/semver". Returns a list of messages, empty when valid.
 */
export function validate(value, schema, schemas = {}) {
  const errors = []
  check(value, schema, schema, '', errors, schemas)
  return errors
}

function check(value, schema, root, path, errors, schemas) {
  const where = path === '' ? 'the file' : path
  for (const key of Object.keys(schema)) {
    if (!KEYWORDS.has(key) && !ANNOTATIONS.has(key)) throw new Error(`Unsupported schema keyword: ${key}`)
  }
  if (schema.$ref !== undefined) {
    const [file, pointer = ''] = schema.$ref.split('#')
    const target = file === '' ? root : schemas[file]
    if (target === undefined) throw new Error(`Schema reference not found: ${schema.$ref}`)
    check(value, lookup(target, pointer), target, path, errors, schemas)
    return
  }
  if (schema.type !== undefined && !matchesType(value, schema.type)) {
    errors.push(`${where}: must be ${schema.type}, found ${typeOf(value)}`)
    return
  }
  if (schema.const !== undefined && value !== schema.const) {
    errors.push(`${where}: must be ${show(schema.const)}, found ${show(value)}`)
  }
  if (schema.enum !== undefined && !schema.enum.includes(value)) {
    errors.push(`${where}: must be one of ${schema.enum.map(show).join(', ')}, found ${show(value)}`)
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${where}: must be at least ${schema.minLength} characters`)
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(`${where}: must be at most ${schema.maxLength} characters, found ${value.length}`)
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) {
      errors.push(`${where}: ${show(value)} does not match the required format`)
    }
  }
  if (typeof value === 'number' && schema.minimum !== undefined && value < schema.minimum) {
    errors.push(`${where}: must be at least ${schema.minimum}`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${where}: must have at least ${schema.minItems} item${schema.minItems === 1 ? '' : 's'}`)
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push(`${where}: must have at most ${schema.maxItems} items`)
    }
    if (schema.uniqueItems === true) {
      const seen = new Set()
      for (const item of value) {
        const key = JSON.stringify(item)
        if (seen.has(key)) errors.push(`${where}: has the duplicate item ${show(item)}`)
        seen.add(key)
      }
    }
    if (schema.items !== undefined) {
      value.forEach((item, index) => check(item, schema.items, root, `${path}[${index}]`, errors, schemas))
    }
  }
  if (typeOf(value) === 'object') {
    for (const name of schema.required ?? []) {
      if (!Object.hasOwn(value, name)) errors.push(`${path === '' ? '' : `${path}.`}${name}: is required`)
    }
    const properties = schema.properties ?? {}
    for (const [name, item] of Object.entries(value)) {
      const next = path === '' ? name : `${path}.${name}`
      if (Object.hasOwn(properties, name)) check(item, properties[name], root, next, errors, schemas)
      else if (schema.additionalProperties === false) errors.push(`${next}: is not a known field`)
    }
  }
}
