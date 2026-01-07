import type { Argv } from "yargs"
import { Session } from "../../session"
import { cmd } from "./cmd"
import { bootstrap } from "../bootstrap"
import { Storage } from "../../storage/storage"
import { Instance } from "../../project/instance"
import { Config } from "../../config/config"
import { EOL } from "os"

async function getBaseUrl() {
  const cfg = await Config.get()
  return cfg.enterprise?.url ?? "https://opncd.ai"
}

function parseShareUrl(input: string): string | undefined {
  const parsed = URL.parse(input)
  if (!parsed) return undefined
  const match = parsed.pathname.match(/^\/(?:share|s)\/([a-zA-Z0-9_-]+)/)
  return match?.[1]
}

export const ImportCommand = cmd({
  command: "import <file>",
  describe: "import session data from JSON file or URL",
  builder: (yargs: Argv) => {
    return yargs.positional("file", {
      describe: "path to JSON file or opencode.ai share URL",
      type: "string",
      demandOption: true,
    })
  },
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      let exportData:
        | {
            info: Session.Info
            messages: Array<{
              info: any
              parts: any[]
            }>
          }
        | undefined

      const isUrl = args.file.startsWith("http://") || args.file.startsWith("https://")

      if (isUrl) {
        const slug = parseShareUrl(args.file)
        if (!slug) {
          process.stdout.write(`Invalid URL format. Expected a share URL with path /share/<id> or /s/<id>`)
          process.stdout.write(EOL)
          return
        }

        const base = await getBaseUrl()
        const response = await fetch(`${base}/api/share/${slug}`)

        if (!response.ok) {
          process.stdout.write(`Failed to fetch share data: ${response.statusText}`)
          process.stdout.write(EOL)
          return
        }

        const data = await response.json()

        if (!data.info || !data.messages || Object.keys(data.messages).length === 0) {
          process.stdout.write(`Share not found: ${slug}`)
          process.stdout.write(EOL)
          return
        }

        exportData = {
          info: data.info,
          messages: Object.values(data.messages).map((msg: any) => {
            const { parts, ...info } = msg
            return {
              info,
              parts,
            }
          }),
        }
      } else {
        const file = Bun.file(args.file)
        exportData = await file.json().catch(() => {})
        if (!exportData) {
          process.stdout.write(`File not found: ${args.file}`)
          process.stdout.write(EOL)
          return
        }
      }

      if (!exportData) {
        process.stdout.write(`Failed to read session data`)
        process.stdout.write(EOL)
        return
      }

      await Storage.write(["session", Instance.project.id, exportData.info.id], exportData.info)

      for (const msg of exportData.messages) {
        await Storage.write(["message", exportData.info.id, msg.info.id], msg.info)

        for (const part of msg.parts) {
          await Storage.write(["part", msg.info.id, part.id], part)
        }
      }

      process.stdout.write(`Imported session: ${exportData.info.id}`)
      process.stdout.write(EOL)
    })
  },
})
