/**
 * Read access to the vendored skill pack: whole files, the attack-class and
 * companion blocks named by `FILE.md#Name` references, the fenced prompt blocks
 * the skill tells the parent to copy verbatim, and the report schema's verdict
 * branches. Every extraction returns the pack's exact text; nothing is
 * paraphrased. The pack is read from the installed package's `skill/` directory,
 * so the vendored files stay the one source of truth.
 * @module @delorun/plugin-security-audit/prompts/skill-text
 */
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** A finding verdict: the discriminant of the report schema's branches. */
export type Verdict = 'confirmed' | 'needs_validation' | 'rejected'

/** Raised when a file, block or marker the caller named is not in the pack. */
export class SkillPackError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SkillPackError'
  }
}

/** The pack's files by name, read once per process. */
const cache = new Map<string, string>()
let root: string | undefined

/**
 * The pack's directory: the nearest `skill/` above this module that holds
 * `SKILL.md`. The source build and the built `lib/index.js` sit at different
 * depths, so the directory is found rather than assumed.
 * @returns the absolute directory path.
 * @throws {SkillPackError} when no installed pack is visible.
 */
export function skillRoot(): string {
  if (root !== undefined) return root
  let directory = dirname(fileURLToPath(import.meta.url))
  for (let up = 0; up < 4; up++) {
    if (existsSync(join(directory, 'skill', 'SKILL.md'))) {
      root = join(directory, 'skill')
      return root
    }
    directory = dirname(directory)
  }
  throw new SkillPackError('the plugin cannot see its vendored skill pack; reinstall the plugin and check that its skill/ directory is present')
}

/**
 * The names of the pack's files, sorted.
 * @returns the file names.
 */
export function skillFileNames(): string[] {
  return [...cache.keys()].sort()
}

/**
 * One pack file's exact text.
 * @param name - the file name, such as `HUNTING.md`.
 * @returns the text.
 * @throws {SkillPackError} naming the directory when the pack has no such file.
 */
export function skillFile(name: string): string {
  const text = cache.get(name)
  if (text !== undefined) return text
  const path = join(skillRoot(), name)
  if (!existsSync(path)) throw new SkillPackError(`the vendored skill pack has no file ${JSON.stringify(name)} at ${path}`)
  const loaded = readFileSync(path, 'utf8')
  cache.set(name, loaded)
  return loaded
}

const HEADING = /^(#{1,6})\s+(.*?)\s*$/
const BOLD_CLASS = /^\*\*([^*]+)\*\*/

/**
 * A heading's block name: its text before any parenthetical qualifier or dash note.
 * @param text - the heading text.
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
 * or heading. These are the reference forms the coverage ledger uses.
 * @param ref - `FILE.md#Name`, where Name is the heading text before any parenthetical or the bold class name.
 * @returns the block, from its heading or bold line through its last line.
 * @throws {SkillPackError} when the reference names no block.
 */
export function skillBlock(ref: string): string {
  const hash = ref.indexOf('#')
  if (hash <= 0 || hash === ref.length - 1) throw new SkillPackError(`${JSON.stringify(ref)} is not a FILE.md#Name block reference`)
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
  if (start < 0) throw new SkillPackError(`${file} has no block named ${JSON.stringify(name)}; its blocks are: ${blockNames(file).join('; ')}`)
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
 * @throws {SkillPackError} when the marker or its fence is missing.
 */
export function fencedBlockAfter(file: string, marker: string): string {
  const lines = skillFile(file).split('\n')
  const at = lines.findIndex(line => line.includes(marker))
  if (at < 0) throw new SkillPackError(`${file} has no line containing ${JSON.stringify(marker)}`)
  const open = lines.findIndex((line, index) => index > at && line.startsWith('```'))
  const close = open < 0 ? -1 : lines.findIndex((line, index) => index > open && line.startsWith('```'))
  if (open < 0 || close < 0) throw new SkillPackError(`${file} has no fenced block after ${JSON.stringify(marker)}`)
  return lines.slice(open + 1, close).join('\n')
}

/**
 * A section's text from its heading to the next heading of the same or a higher level.
 * @param file - the pack file.
 * @param heading - the exact heading text without its `#` marks.
 * @returns the section including its heading line.
 * @throws {SkillPackError} when the heading is missing.
 */
export function sectionText(file: string, heading: string): string {
  return skillBlock(`${file}#${headingName(heading)}`)
}

/** One branch of the report schema's `oneOf`. */
interface ReportSchemaBranch {
  readonly properties: { readonly verdict: { readonly const: string } }
}

/** The report schema as far as the prompt composer reads it. */
interface ReportSchemaDocument {
  readonly items: { readonly oneOf: readonly ReportSchemaBranch[] }
}

/**
 * The report schema's branch for one verdict, as the skill tells the parent to copy it into prompts.
 * @param verdict - the branch's verdict.
 * @returns the branch as indented JSON.
 * @throws {SkillPackError} when the vendored schema has no such branch.
 */
export function schemaBranch(verdict: Verdict): string {
  const document = JSON.parse(skillFile('report-schema.json')) as ReportSchemaDocument
  const branch = document.items.oneOf.find(candidate => candidate.properties.verdict.const === verdict)
  if (branch === undefined) throw new SkillPackError(`report-schema.json has no ${verdict} branch`)
  return JSON.stringify(branch, undefined, 2)
}

