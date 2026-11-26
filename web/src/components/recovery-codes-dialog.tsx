import * as React from "react"
import { Download, LifeBuoy } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { CopyButton } from "./copy-button"

function download(codes: string[]) {
  const text =
    "Leazone - codes de secours\n" +
    `Créés le ${new Date().toLocaleString("fr-FR")}\n` +
    "Chaque code ne marche qu'une seule fois.\n\n" +
    codes.join("\n") +
    "\n"
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }))
  const a = document.createElement("a")
  a.href = url
  a.download = "leazone-codes-de-secours.txt"
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Shows freshly generated recovery codes. Cannot be closed until the user confirms. */
export function RecoveryCodesDialog({
  codes,
  onDone,
}: {
  codes: string[] | null
  onDone: () => void
}) {
  const [saved, setSaved] = React.useState(false)
  React.useEffect(() => setSaved(false), [codes])
  const open = !!codes && codes.length > 0
  return (
    <Dialog open={open}>
      <DialogContent
        showCloseButton={false}
        onEscapeKeyDown={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
        className="sm:max-w-md"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <LifeBuoy className="size-5" /> Codes de secours
          </DialogTitle>
          <DialogDescription>
            Gardez ces codes en lieu sûr. Ils permettent de vous connecter si vous perdez votre passkey ou
            votre téléphone. Chaque code ne marche qu'une fois. Ils ne seront plus affichés.
          </DialogDescription>
        </DialogHeader>
        <ol className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-lg border bg-muted/40 p-4 font-mono text-sm">
          {codes?.map((c) => (
            <li key={c} className="select-all">
              {c}
            </li>
          ))}
        </ol>
        <div className="flex flex-wrap gap-2">
          <CopyButton value={codes?.join("\n") ?? ""} />
          <Button type="button" variant="outline" onClick={() => codes && download(codes)}>
            <Download /> Télécharger (.txt)
          </Button>
        </div>
        <div className="flex items-start gap-2 pt-2">
          <Checkbox id="codes-saved" checked={saved} onCheckedChange={(v) => setSaved(v === true)} />
          <Label htmlFor="codes-saved" className="leading-snug font-normal">
            J'ai enregistré ces codes
          </Label>
        </div>
        <DialogFooter>
          <Button type="button" disabled={!saved} onClick={onDone}>
            Continuer
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
