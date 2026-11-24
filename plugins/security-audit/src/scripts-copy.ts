/**
 * The working copy every audit role runs in: the reviewed tree extracted from
 * the target's Git repository, and the two refusals that bound a run's copies.
 *
 * The copy method is `git archive | tar` (owner ruling A644). It writes only
 * what the revision tracks, so a copy is the reviewed tree with no untracked
 * junk, and it was measured at 1.6 s / 260 MB over 26 041 files against 49 s /
 * 512 MB over 41 000 files for a filesystem copy. Hardlinks are not used (a
 * write through one copy changes the source), reflink is not relied on (this
 * filesystem is ext4), and bubblewrap 0.9.0 has no overlay.
 *
 * A copy is the role's cwd and its only writable root. It is disposable: the
 * role's artifacts are promoted out of it and the copy is removed when the role
 * finishes.
 * @module @delorun/plugin-security-audit/scripts-copy
 */
import { spawn } from 'node:child_process'
import { lstat, mkdir, readdir, rm, statfs } from 'node:fs/promises'
import { join } from 'node:path'
import type { WorkCopy } from './types.ts'

/** The most live copies one run holds at once: one wave of four hunters, the same as reconnaissance. */
export const MAX_LIVE_COPIES = 4

/** The free disk a run needs before it makes another copy: 2 GiB, about eight copies of a 260 MB target. */
export const DISK_FLOOR_BYTES = 2 * 1024 * 1024 * 1024

/** How many nested harness starts one run allows. */
export const NESTED_HARNESS_CAP = 2

/** The ports a nested harness may listen on, in order. */
export const NESTED_PORT_RANGE: readonly number[] = [19988, 19989, 19990, 19991, 19992, 19993, 19994, 19995, 19996, 19997]

/** What a copy measures. */
export interface CopyMeasurement {
  /** Its bytes. */
  readonly bytes: number
  /** How many files it holds. */
  readonly files: number
}

/**
 * State a byte count in the units a person reads.
 * @param bytes - the count.
 * @returns megabytes, or gigabytes with one decimal place.
 */
export function bytesText(bytes: number): string {
  const mebibytes = bytes / (1024 * 1024)
  if (mebibytes >= 1024) return (mebibytes / 1024).toFixed(1) + ' GB'
  return String(Math.round(mebibytes)) + ' MB'
}

/**
 * The free space on the filesystem holding a path.
 * @param path - the path.
 * @returns the bytes available to this user.
 */
export async function freeDiskBytes(path: string): Promise<number> {
  const info = await statfs(path)
  return Number(info.bavail) * Number(info.bsize)
}

/**
 * Measure a directory tree: its bytes and its file count, without following a
 * symbolic link out of the tree.
 * @param root - the absolute directory.
 * @returns the measurement.
 */
export async function measureTree(root: string): Promise<CopyMeasurement> {
  let bytes = 0
  let files = 0
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) {
        await walk(path)
        continue
      }
      files += 1
      if (entry.isFile()) bytes += (await lstat(path)).size
    }
  }
  await walk(root)
  return { bytes, files }
}

/** What one role's copy start is checked against before it copies. */
export interface CopyGate {
  /** How many copies the run currently holds. */
  readonly live: number
  /** The free space on the run's filesystem. */
  readonly freeBytes: number
  /** What a copy of this target measured the last time the run made one, when it made one. */
  readonly measured?: CopyMeasurement | undefined
}

/**
 * Why a role may not be given a working copy, if it may not.
 * @param gate - what the run holds and what is free.
 * @returns the refusal, naming the floor or the cap and what a copy measures, or `undefined` when a copy may start.
 */
export function copyGateProblem(gate: CopyGate): string | undefined {
  const size = gate.measured === undefined
    ? 'this run has not copied the target yet, so its size is not measured'
    : 'one copy of this target measures ' + bytesText(gate.measured.bytes) + ' over ' + String(gate.measured.files) + ' files'
  if (gate.freeBytes < DISK_FLOOR_BYTES) {
    return 'free disk is ' + bytesText(gate.freeBytes) + ', below the ' + bytesText(DISK_FLOOR_BYTES) + ' floor a run needs before it copies a role\u2019s working copy, and ' + size + '. Free space on the disk holding this run, then retry the role.'
  }
  if (gate.live >= MAX_LIVE_COPIES) {
    return 'this run already holds ' + String(gate.live) + ' live working copies, its cap of ' + String(MAX_LIVE_COPIES) + ', and ' + size + '. Let a role finish, then retry this one.'
  }
  return undefined
}

/**
 * Extract a revision of the target into a fresh directory.
 * @param input - the target repository, the revision, the destination and whether the copy is the reviewed tree.
 * @returns what the copy holds, how long it took and what it measures.
 * @throws {Error} naming the failing command and its standard error.
 */
export async function createWorkCopy(input: {
  readonly target: string
  readonly revision: string
  readonly destination: string
  readonly reviewed: boolean
  readonly signal?: AbortSignal | undefined
}): Promise<WorkCopy> {
  const started = Date.now()
  await rm(input.destination, { recursive: true, force: true })
  await mkdir(input.destination, { recursive: true })
  const git = spawn('git', ['-C', input.target, '-c', 'core.fsmonitor=false', 'archive', '--format=tar', input.revision], {
    stdio: ['ignore', 'pipe', 'pipe'],
    signal: input.signal,
  })
  const tar = spawn('tar', ['-x', '-f', '-', '-C', input.destination], { stdio: [git.stdout, 'ignore', 'pipe'], signal: input.signal })
  git.stdout.destroy()
  const failures: string[] = []
  const wait = (child: ReturnType<typeof spawn>, name: string): Promise<void> => new Promise((resolve, reject) => {
    let stderr = ''
    child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString() })
    child.on('error', reject)
    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      if (code === 0) resolve()
      else failures.push(name + ' ended with ' + (code === null ? 'signal ' + String(signal) : 'code ' + String(code)) + (stderr.trim() === '' ? '' : ': ' + stderr.trim()))
      resolve()
    })
  })
  await Promise.all([wait(git, 'git archive'), wait(tar, 'tar')])
  if (failures.length > 0) {
    await rm(input.destination, { recursive: true, force: true })
    throw new Error('the working copy could not be made from ' + input.revision + ' in ' + input.target + ': ' + failures.join('; '))
  }
  const measured = await measureTree(input.destination)
  return {
    path: '',
    revision: input.revision,
    reviewed: input.reviewed,
    bytes: measured.bytes,
    files: measured.files,
    seconds: Math.round((Date.now() - started) / 100) / 10,
    created_at: new Date().toISOString(),
    removed_at: null,
  }
}

/**
 * Remove a role's working copy, keeping everything outside it.
 * @param destination - the absolute copy directory.
 */
export async function removeWorkCopy(destination: string): Promise<void> {
  await rm(destination, { recursive: true, force: true })
}
