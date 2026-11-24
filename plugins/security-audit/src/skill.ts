/**
 * Read access to the vendored skill pack: whole files, attack-class and
 * companion blocks named by `FILE.md#Name` references, the fenced prompt
 * blocks the skill tells the coordinator to copy verbatim, the report schema's
 * verdict branches, and the skill's own two validators. Every extraction
 * returns the pack's exact text, read from `skill/` beside the built module.
 * @module @delorun/plugin-security-audit/skill
 */
import { createRequire } from 'node:module'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/** A finding verdict, the discriminant of the report schema's branches. */
export type Verdict = 'confirmed' | 'needs_validation' | 'rejected'

/** Raised when a file, block or marker the caller named is not in the pack. */
export class SkillReferenceError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SkillReferenceError'
  }
}

/** The shape the skill's findings validator exports. */
export interface FindingsValidator {
  /**
   * Validate a findings document against the report schema and the skill's semantic rules.
   * @param findings - the parsed `findings.json` array.
   * @param schema - the parsed `report-schema.json`.
   * @returns the error messages, empty when valid.
   */
  validateDocument(findings: unknown, schema: unknown): string[]
}

/** The shape the skill's coverage-ledger validator exports. */
export interface LedgerValidator {
  /**
   * Validate a coverage ledger.
   * @param ledger - the parsed `coverage-ledger.json` array.
   * @returns the error messages, empty when valid.
   */
  validateDocument(ledger: unknown): string[]
  /**
   * Derive a unit's coverage id from its canonical references.
   * @param refs - the `canonical_refs` object.
   * @returns the id.
   * @throws {TypeError} when a reference is not canonical.
   */
  canonicalCoverageId(refs: unknown): string
  /**
   * @param value - a candidate agent id.
   * @returns whether it is a canonical lowercase agent id.
   */
  isSafeAgentId(value: unknown): boolean
  /**
   * @param value - a candidate repository-relative path.
   * @returns whether it is a safe relative path.
   */
  isSafeRelativePath(value: unknown): boolean
}

/** The pack directory, beside the built module in `lib/` and beside the source in `src/`. */
const PACK = fileURLToPath(new URL('../skill/', import.meta.url))

/** File texts already read, so a prompt built from several blocks reads each file once. */
const texts = new Map<string, string>()

const require = createRequire(import.meta.url)

/** The skill's findings validator (`skill/validate-findings.cjs`). */
export const findingsValidator: FindingsValidator = require(fileURLToPath(new URL('validate-findings.cjs', new URL('../skill/', import.meta.url))))

/** The skill's coverage-ledger validator (`skill/validate-coverage-ledger.cjs`). */
export const ledgerValidator: LedgerValidator = require(fileURLToPath(new URL('validate-coverage-ledger.cjs', new URL('../skill/', import.meta.url))))

/**
 * The names of the pack's files, sorted.
 * @returns the file names.
 */
export function skillFileNames(): string[] {
  return readdirSync(PACK, { withFileTypes: true })
    .filter(entry => entry.isFile())
    .map(entry => entry.name)
    .sort()
}

/**
 * One pack file's text.
 * @param name - the file name, such as `HUNTING.md`.
 * @returns the text.
 * @throws {SkillReferenceError} naming the available files when the pack has no such file.
 */
export function skillFile(name: string): string {
  const known = texts.get(name)
  if (known !== undefined) return known
  if (name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
    throw new SkillReferenceError(`${JSON.stringify(name)} is not a file in the skill pack`)
  }
  const names = skillFileNames()
  if (!names.includes(name)) {
    throw new SkillReferenceError(`the skill pack has no file ${JSON.stringify(name)}; it has ${names.join(', ')}`)
  }
  const text = readFileSync(`${PACK}${name}`, 'utf8')
  texts.set(name, text)
  return text
}

const HEADING = /^(#{1,6})\s+(.*?)\s*$/
const BOLD_CLASS = /^\*\*([^*]+)\*\*/

/**
 * A heading's block name: its text before any parenthetical qualifier or dash note.
 * @param text - the heading's text.
 * @returns the block name.
 */
function headingName(text: string): string {
  return text.replace(/\s+\(.*$/u, '').replace(/\s+—.*$/u, '').trim()
}

/**
 * The names a file's blocks can be referenced by: its headings and its bold attack classes.
 * @param file - the pack file.
 * @returns the names in file order.
 */
export function blockNames(file: string): string[] {
  const names: string[] = []
  for (const line of skillFile(file).split('\n')) {
    const heading = HEADING.exec(line)
    if (heading !== null) names.push(headingName(heading[2] ?? ''))
    const bold = BOLD_CLASS.exec(line)
    if (bold !== null) names.push((bold[1] ?? '').trim())
  }
  return names
}

/**
 * The exact text of one block. A heading block runs to the next heading of the
 * same or a higher level; a bold attack-class block runs to the next bold class
 * or heading. These are the reference forms the skill's coverage ledger uses.
 * @param ref - `FILE.md#Name`, where Name is the heading text before any parenthetical or the bold class name.
 * @returns the block, from its heading or bold line through its last line.
 * @throws {SkillReferenceError} when the reference names no block.
 */
export function skillBlock(ref: string): string {
  const hash = ref.indexOf('#')
  if (hash <= 0 || hash === ref.length - 1) throw new SkillReferenceError(`${JSON.stringify(ref)} is not a FILE.md#Name block reference`)
  const file = ref.slice(0, hash)
  const name = ref.slice(hash + 1)
  const lines = skillFile(file).split('\n')
  let start = -1
  let level = 0
  let bold = false
  for (const [index, line] of lines.entries()) {
    const heading = HEADING.exec(line)
    if (heading !== null && headingName(heading[2] ?? '') === name) {
      start = index
      level = (heading[1] ?? '').length
      break
    }
    const boldMatch = BOLD_CLASS.exec(line)
    if (boldMatch !== null && (boldMatch[1] ?? '').trim() === name) {
      start = index
      bold = true
      break
    }
  }
  if (start < 0) throw new SkillReferenceError(`${file} has no block named ${JSON.stringify(name)}; its blocks are: ${blockNames(file).join('; ')}`)
  let end = lines.length
  for (let index = start + 1; index < lines.length; index++) {
    const line = lines[index] ?? ''
    const heading = HEADING.exec(line)
    if (heading !== null && (bold || (heading[1] ?? '').length <= level)) {
      end = index
      break
    }
    if (bold && BOLD_CLASS.test(line)) {
      end = index
      break
    }
  }
  return lines.slice(start, end).join('\n').trimEnd()
}

/**
 * The inner text of the first fenced block after the line containing a marker.
 * The skill marks every block it requires verbatim in a prompt this way.
 * @param file - the pack file.
 * @param marker - text that occurs on the line before the fence, such as a heading.
 * @returns the fenced text without its fence lines.
 * @throws {SkillReferenceError} when the marker or its fence is missing.
 */
export function fencedBlockAfter(file: string, marker: string): string {
  const lines = skillFile(file).split('\n')
  const at = lines.findIndex(line => line.includes(marker))
  if (at < 0) throw new SkillReferenceError(`${file} has no line containing ${JSON.stringify(marker)}`)
  const open = lines.findIndex((line, index) => index > at && line.startsWith('```'))
  const close = open < 0 ? -1 : lines.findIndex((line, index) => index > open && line.startsWith('```'))
  if (open < 0 || close < 0) throw new SkillReferenceError(`${file} has no fenced block after ${JSON.stringify(marker)}`)
  return lines.slice(open + 1, close).join('\n')
}

/**
 * A section's text from its heading to the next heading of the same or a higher level.
 * @param file - the pack file.
 * @param heading - the exact heading text without its `#` marks.
 * @returns the section including its heading line.
 * @throws {SkillReferenceError} when the heading is missing.
 */
export function sectionText(file: string, heading: string): string {
  return skillBlock(`${file}#${headingName(heading)}`)
}

/** The parsed `report-schema.json`. */
export const REPORT_SCHEMA: unknown = JSON.parse(skillFile('report-schema.json'))

/**
 * The report schema's branch for one verdict, as the skill tells the coordinator to copy it into prompts.
 * @param verdict - the branch's verdict.
 * @returns the branch as indented JSON.
 * @throws {SkillReferenceError} when the schema has no such branch.
 */
export function schemaBranch(verdict: Verdict): string {
  const items = (REPORT_SCHEMA as { items: { oneOf: { properties: { verdict: { const: string } } }[] } }).items
  const branch = items.oneOf.find(candidate => candidate.properties.verdict.const === verdict)
  if (branch === undefined) throw new SkillReferenceError(`report-schema.json has no ${verdict} branch`)
  return JSON.stringify(branch, undefined, 2)
}
