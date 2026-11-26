/*
 * Optional modules. Phase 5 turns these on (later: from the server).
 * Pages behind a disabled module are hidden from the sidebar and ⌘K.
 */
export const modules = {
  blocking: false,
  dnssec: false,
} as const

export type ModuleName = keyof typeof modules
