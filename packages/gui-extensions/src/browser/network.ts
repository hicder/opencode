import { session, type WebContents } from "electron"
import type { RpcClient } from "@opencode/client/effect/api"
import type { Session } from "@opencode/schema/session"
import { Browser } from "@opencode/plugin-browser/rpc"
import { BrowserProxy } from "@opencode/plugin-browser/proxy"
import { Effect, Encoding, Exit, RcMap, Scope } from "effect"

export type BrowserNetworks = ReturnType<typeof createBrowserNetworks>
export type BrowserNetwork = Effect.Success<ReturnType<BrowserNetworks["join"]>>

// One attachment's server connection. The server scopes tunnels to it and closes them with it.
type Member = {
  rpc: RpcClient<typeof Browser.Definition, unknown>
  attachment: { sessionID: Session.ID; connectionID: string }
  options: { location: { directory: string; workspace?: string } }
}

/**
 * Partitions outlive any single attachment so logins persist across sessions, which means a partition's
 * proxy cannot belong to one attachment either. Each partition has one proxy, opened by its first attachment
 * and closed with its last. The proxy sends every new connection through whichever attachment is live, and
 * keeps reads, writes, and closes on the attachment that opened the tunnel.
 */
export function createBrowserNetworks() {
  const scope = Scope.makeUnsafe()
  const partitions = Effect.runSync(
    RcMap.make({
      lookup: Effect.fn("BrowserNetworks.partition")(function* (name: string) {
        const members = new Set<Member>()
        const tunnels = new Map<string, Member>()
        const owner = (id: string) => {
          const member = tunnels.get(id)
          if (!member) throw new Error("Browser tunnel is closed or unknown.")
          return member
        }
        const proxy = yield* Effect.acquireRelease(
          Effect.tryPromise(() =>
            BrowserProxy.make({
              open: async (target, signal) => {
                // The server limits each attachment's connections, so use the least loaded one.
                const member = Array.from(members, (member) => ({
                  member,
                  load: Array.from(tunnels.values()).filter((owner) => owner === member).length,
                })).sort((a, b) => a.load - b.load)[0]?.member
                if (!member) throw new Error("No session is connected to carry the browser's network traffic.")
                const id = await Effect.runPromise(
                  member.rpc["tunnel.open"]({ ...member.attachment, target }, member.options),
                  { signal },
                )
                tunnels.set(id, member)
                return id
              },
              read: async (tunnelID, signal) => {
                const member = owner(tunnelID)
                return await Effect.runPromise(
                  member.rpc["tunnel.read"]({ ...member.attachment, tunnelID }, member.options),
                  { signal },
                )
              },
              write: async (tunnelID, data, end, signal) => {
                const member = owner(tunnelID)
                return await Effect.runPromise(
                  member.rpc["tunnel.write"](
                    { ...member.attachment, tunnelID, data: Encoding.encodeBase64(data), end },
                    member.options,
                  ),
                  { signal },
                )
              },
              close: async (tunnelID) => {
                const member = tunnels.get(tunnelID)
                tunnels.delete(tunnelID)
                if (!member) return
                await Effect.runPromise(
                  member.rpc["tunnel.close"]({ ...member.attachment, tunnelID }, member.options).pipe(
                    Effect.timeout("5 seconds"),
                  ),
                )
              },
            }),
          ),
          (proxy) => Effect.promise(() => proxy.close()),
        )
        const partition = session.fromPartition(name)
        yield* Effect.addFinalizer(() => Effect.promise(() => partition.closeAllConnections()))
        // This is the browser's private partition, not the app/API connection. Never
        // bypass localhost: it must resolve on the machine running the OC2 server.
        yield* Effect.tryPromise(() =>
          partition.setProxy({ mode: "fixed_servers", proxyRules: proxy.url, proxyBypassRules: "<-loopback>" }),
        )
        yield* Effect.tryPromise(() => partition.closeAllConnections())
        return { proxy, members, tunnels }
      }),
    }).pipe(Scope.provide(scope)),
  )

  return {
    /** Joins the partition's proxy for as long as the calling scope (the attachment) lives. */
    join: Effect.fn("BrowserNetworks.join")(function* (input: {
      partition: string
      rpc: Member["rpc"]
      attachment: Member["attachment"]
      location: Member["options"]["location"]
    }) {
      const shared = yield* RcMap.get(partitions, input.partition)
      const member: Member = { rpc: input.rpc, attachment: input.attachment, options: { location: input.location } }
      shared.members.add(member)
      yield* Effect.addFinalizer(() =>
        Effect.sync(() => {
          shared.members.delete(member)
          shared.tunnels.forEach((owner, id) => {
            if (owner === member) shared.tunnels.delete(id)
          })
        }),
      )
      return {
        attach(contents: WebContents) {
          const login = (
            event: Electron.Event,
            _details: Electron.AuthenticationResponseDetails,
            auth: Electron.AuthInfo,
            callback: (username?: string, password?: string) => void,
          ) => {
            if (
              !auth.isProxy ||
              auth.scheme !== "basic" ||
              auth.host !== shared.proxy.host ||
              auth.port !== shared.proxy.port ||
              auth.realm !== "OpenCode Browser Proxy"
            )
              return
            event.preventDefault()
            callback(shared.proxy.credentials.username, shared.proxy.credentials.password)
          }
          contents.on("login", login)
          contents.setWebRTCIPHandlingPolicy("disable_non_proxied_udp")
          return () => contents.off("login", login)
        },
      }
    }),
    dispose: () => Effect.runPromise(Scope.close(scope, Exit.void)),
  }
}
