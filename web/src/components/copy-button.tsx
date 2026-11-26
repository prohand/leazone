import * as React from "react"
import { Check, Copy } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"

export async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    toast.error("Copie impossible. Sélectionnez le texte et copiez-le à la main.")
    return false
  }
}

export function CopyButton({
  value,
  label = "Copier",
  iconOnly = false,
  variant = "outline",
  size,
}: {
  value: string
  label?: string
  iconOnly?: boolean
  variant?: React.ComponentProps<typeof Button>["variant"]
  size?: React.ComponentProps<typeof Button>["size"]
}) {
  const [done, setDone] = React.useState(false)
  const onClick = async () => {
    if (await copyText(value)) {
      setDone(true)
      window.setTimeout(() => setDone(false), 1500)
    }
  }
  const Icon = done ? Check : Copy
  return (
    <Button
      type="button"
      variant={variant}
      size={size ?? (iconOnly ? "icon" : "default")}
      onClick={onClick}
      aria-label={label}
      title={label}
    >
      <Icon />
      {!iconOnly && (done ? "Copié" : label)}
    </Button>
  )
}
