import { TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { CopyButton } from "./copy-button"

/** Displays a secret (temporary password, API token) that the server returns only once. */
export function SecretOnceDialog({
  title,
  description,
  secret,
  onClose,
}: {
  title: string
  description?: string
  secret: string | null
  onClose: () => void
}) {
  return (
    <Dialog open={!!secret} onOpenChange={(o) => !o && onClose()}>
      <DialogContent onInteractOutside={(e) => e.preventDefault()} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm break-all select-all">
            {secret}
          </code>
          <CopyButton value={secret ?? ""} iconOnly />
        </div>
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <TriangleAlert className="size-4 text-warning" />
          Copiez-le maintenant : il ne sera plus affiché.
        </p>
        <DialogFooter>
          <Button onClick={onClose}>J'ai copié</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
