/**
 * Lossless JSON helpers for tool answers. A tool's output schema is the
 * authority on what a value holds, and its render function reads only what the
 * schema declares; these helpers carry a domain object into that plain shape
 * without a cast to `unknown`.
 * @module delorun-plugin-security-audit/tools/json
 */

/** A lossless JSON value, as a tool answer may carry it. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

/**
 * Project domain objects into the plain JSON a tool answer carries.
 * @param values - the domain objects.
 * @returns the same data as plain JSON records.
 */
export function jsonArray<T>(values: readonly T[]): Record<string, Json>[] {
  return JSON.parse(JSON.stringify(values)) as Record<string, Json>[]
}

/**
 * Project one domain object into the plain JSON a tool answer carries.
 * @param value - the domain object.
 * @returns the same data as a plain JSON record.
 */
export function jsonObject<T>(value: T): Record<string, Json> {
  return JSON.parse(JSON.stringify(value)) as Record<string, Json>
}
