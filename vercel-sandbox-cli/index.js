import { execSync } from "node:child_process"
import { existsSync } from "node:fs"
import { Sandbox } from "@vercel/sandbox"

function exec(command) {
  try {
    return execSync(command, { encoding: "utf-8", stdio: "pipe" }).trim()
  } catch {
    return null
  }
}

function checkVercelAuth() {
  const result = exec("vercel whoami")
  if (!result) {
    console.error("Error: Not logged in to Vercel.")
    console.error("Run: vercel login")
    process.exit(1)
  }
  console.log(`Authenticated as: ${result}`)
}

function checkVercelLink() {
  if (!existsSync(".vercel/project.json")) {
    console.error("Error: Project not linked to Vercel.")
    console.error("Run: vercel link")
    process.exit(1)
  }
  console.log("Project linked to Vercel")
}

async function main() {
  checkVercelAuth()
  checkVercelLink()

  console.log("Creating sandbox...")
  const sandbox = await Sandbox.create()

  const { exitCode } = await sandbox.runCommand({
    cmd: "node",
    args: ["-e", "process.exit(0)"],
  })

  console.log(exitCode === 0 ? "ok" : "failed")

  await sandbox.stop()
}

main().catch((error) => {
  console.error("Error:", error.message)
  process.exit(1)
})
