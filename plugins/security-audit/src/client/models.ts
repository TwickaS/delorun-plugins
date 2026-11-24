/**
 * The model catalogue the strip's per-role menus read. The Host answers it from
 * the adapters it has loaded, so the catalogue is read on demand, refreshed when
 * an adapter changes, and dropped when the connection is replaced.
 * @module @delorun/plugin-security-audit/client/models
 */
import { createSnapshotStore, type SnapshotStore } from '@deepseek-ai/dsh-client-store'
import type { Context as ClientContext } from '@deepseek-ai/cordis'
// Type-only: the ctx.remote Context merge and its model catalogue call.
import type {} from '@deepseek-ai/dsh-api-remotes/client'
import type { ModelProviderGroup } from '@deepseek-ai/dsh-api-remotes/client'

/** What the strip's model menus can offer. */
export interface ModelCatalogState {
  /** Where the last request settled. */
  readonly status: 'idle' | 'loading' | 'ready' | 'error'
  /** The providers with their models, grouped as each adapter reports them. */
  readonly groups: readonly ModelProviderGroup[]
}

/**
 * One session-independent reader of the Host model catalogue.
 *
 * The catalogue is shared by every chat's strip, so one reader serves them all;
 * the menu reads its snapshot and the strip asks for a load when it appears.
 */
export class AuditModelCatalog {
  /** The current catalogue. */
  readonly state: SnapshotStore<ModelCatalogState> = createSnapshotStore({ status: 'idle', groups: [] })

  private readonly ctx: ClientContext
  private generation = 0
  private disposed = false

  /** @param ctx - the browser plugin context, whose `remote.session` answers the catalogue. */
  constructor(ctx: ClientContext) {
    this.ctx = ctx
  }

  /** Read the catalogue once, unless a read is already in flight. */
  load(): void {
    const snapshot = this.state.getSnapshot()
    if (this.disposed || snapshot.status === 'loading' || snapshot.status === 'ready') return
    const generation = this.generation
    this.state.set({ status: 'loading', groups: snapshot.groups })
    void (async () => {
      const response = await this.ctx.remote.session.modelCatalog()
      if (this.disposed || generation !== this.generation) return
      this.state.set(response.ok
        ? { status: 'ready', groups: response.value.groups }
        : { status: 'error', groups: [] })
    })()
  }

  /** Read the catalogue again after an adapter or settings change. */
  refresh(): void {
    if (this.disposed) return
    this.generation += 1
    this.state.set({ status: 'idle', groups: this.state.getSnapshot().groups })
    this.load()
  }

  /** Stop answering; a late request result is dropped. */
  dispose(): void {
    this.disposed = true
    this.generation += 1
  }
}
