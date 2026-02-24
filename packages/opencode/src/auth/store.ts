/**
 * File-based credential store for opencode.
 *
 * Persists credentials as JSON at $XDG_DATA_HOME/opencode/webfetch-auth.json
 * with mode 0o600 (directory 0o700). Uses an in-memory mutex to serialize
 * concurrent operations and atomic writes (write-then-rename) to prevent
 * corruption on crash.
 */

import path from "path"
import { mkdir, writeFile, rename } from "fs/promises"
import { Global } from "../global"
import type { CredentialStore, Credential } from "./webfetch-auth"

type Store = Record<string, Credential>

export class FileCredentialStore implements CredentialStore {
  private lock = Promise.resolve()

  constructor(private filepath = path.join(Global.Path.data, "webfetch-auth.json")) {}

  private serialized<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.lock
    let release!: () => void
    this.lock = new Promise<void>((r) => {
      release = r
    })
    return prev.then(fn).finally(release)
  }

  private async load(): Promise<Store> {
    try {
      return JSON.parse(await Bun.file(this.filepath).text()) as Store
    } catch {
      return {}
    }
  }

  private async save(store: Store) {
    // Ensure parent directory exists with 0o700 so other users cannot list
    // the directory contents, even though the file itself is 0o600.
    await mkdir(path.dirname(this.filepath), { recursive: true, mode: 0o700 })
    // Atomic write: write to a temp file then rename. Prevents credential
    // store corruption on crash — rename() is atomic on POSIX filesystems.
    const tmp = this.filepath + ".tmp"
    await writeFile(tmp, JSON.stringify(store, null, 2), { mode: 0o600 })
    await rename(tmp, this.filepath)
  }

  async get(resource: string): Promise<Credential | undefined> {
    return this.serialized(async () => {
      const store = await this.load()
      return store[resource]
    })
  }

  async set(resource: string, cred: Credential): Promise<void> {
    return this.serialized(async () => {
      const store = await this.load()
      store[resource] = cred
      await this.save(store)
    })
  }

  async remove(resource: string): Promise<void> {
    return this.serialized(async () => {
      const store = await this.load()
      delete store[resource]
      await this.save(store)
    })
  }

  async all(): Promise<Record<string, Credential>> {
    return this.serialized(async () => {
      return this.load()
    })
  }
}
