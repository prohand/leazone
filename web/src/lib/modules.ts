import { useQuery } from "@tanstack/react-query"
import { modulesQuery } from "@/api/queries"
import type { Modules } from "@/api/types"

/*
 * Optional modules, as set on the server (Paramètres > Modules).
 * Pages behind a disabled module are hidden from the sidebar and ⌘K, and
 * their routes show a short "Module désactivé" card.
 */
export type ModuleName = "blocking" | "dnssec"

export type ModuleState = Required<Modules> & {
  /** The server answered (false while loading, or on an old server). */
  loaded: boolean
}

const allOff: Required<Modules> = { blocking: false, dnssec: false, dnssecValidation: false }

export function modulesOf(data?: Modules): Required<Modules> {
  return {
    blocking: data?.blocking === true,
    dnssec: data?.dnssec === true,
    dnssecValidation: data?.dnssecValidation === true,
  }
}

/** Modules state; everything off while loading. */
export function useModules(): ModuleState & { pending: boolean } {
  const q = useQuery(modulesQuery)
  return { ...(q.data ? modulesOf(q.data) : allOff), loaded: !!q.data, pending: q.isPending }
}
