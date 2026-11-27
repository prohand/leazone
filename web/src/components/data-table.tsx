import * as React from "react"
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type Column,
  type ColumnDef,
  type FilterFn,
  type RowData,
  type SortingState,
} from "@tanstack/react-table"
import { ArrowDown, ArrowUp, ArrowUpDown, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"

declare module "@tanstack/react-table" {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Classes added to the column's header and cells, e.g. "hidden sm:table-cell" to hide it on small screens. */
    className?: string
  }
}

/** Sortable column header. */
export function SortHeader<T>({ column, title }: { column: Column<T, unknown>; title: string }) {
  const dir = column.getIsSorted()
  const Icon = dir === "asc" ? ArrowUp : dir === "desc" ? ArrowDown : ArrowUpDown
  return (
    <Button
      variant="ghost"
      size="sm"
      className="-ml-2 h-8 px-2 data-[active=true]:text-foreground"
      data-active={!!dir}
      onClick={() => column.toggleSorting(dir === "asc")}
    >
      {title}
      <Icon className={cn("size-3.5", !dir && "opacity-40")} />
    </Button>
  )
}

// Case and accent insensitive "contains".
const normalize = (s: string) => s.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase()
const containsFilter: FilterFn<unknown> = (row, columnId, value: string) => {
  const v = row.getValue(columnId)
  if (v === null || v === undefined) return false
  return normalize(String(v)).includes(normalize(value))
}

export function DataTable<T>({
  columns,
  data,
  loading,
  searchPlaceholder = "Rechercher…",
  toolbar,
  empty = "Aucun élément.",
  emptyFiltered = "Aucun résultat.",
  initialSorting = [],
  getRowId,
  onRowClick,
  rowClassName,
  search,
  onSearchChange,
  searchAutoFocus,
}: {
  columns: ColumnDef<T, unknown>[]
  data: T[] | undefined
  loading?: boolean
  searchPlaceholder?: string
  toolbar?: React.ReactNode
  empty?: React.ReactNode
  /** Shown instead of `empty` when the search finds nothing. */
  emptyFiltered?: React.ReactNode
  initialSorting?: SortingState
  getRowId?: (row: T) => string
  /** Makes rows clickable (and keyboard focusable). */
  onRowClick?: (row: T) => void
  rowClassName?: (row: T) => string | undefined
  /** Controlled search text (e.g. kept in the URL); uncontrolled when omitted. */
  search?: string
  onSearchChange?: (value: string) => void
  searchAutoFocus?: boolean
}) {
  const [sorting, setSorting] = React.useState<SortingState>(initialSorting)
  const [ownFilter, setOwnFilter] = React.useState("")
  const globalFilter = search ?? ownFilter
  const setGlobalFilter = (v: string) => (onSearchChange ? onSearchChange(v) : setOwnFilter(v))

  const table = useReactTable<T>({
    data: data ?? [],
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: (u) => setGlobalFilter(String((typeof u === "function" ? u(globalFilter) : u) ?? "")),
    globalFilterFn: containsFilter as FilterFn<T>,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getRowId,
  })

  const rows = table.getRowModel().rows
  const colCount = table.getVisibleLeafColumns().length

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative sm:max-w-xs sm:flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            placeholder={searchPlaceholder}
            autoFocus={searchAutoFocus}
            className="pl-8"
            aria-label="Rechercher"
          />
        </div>
        {toolbar && <div className="flex flex-wrap items-center gap-2 sm:ml-auto">{toolbar}</div>}
      </div>
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((h) => (
                  <TableHead key={h.id} className={cn("text-xs text-muted-foreground", h.column.columnDef.meta?.className)}>
                    {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {loading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <TableRow key={i}>
                  {Array.from({ length: colCount }).map((__, j) => (
                    <TableCell key={j}>
                      <Skeleton className="h-4 w-full max-w-32" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : rows.length === 0 ? null : (
              rows.map((row) => (
                <TableRow
                  key={row.id}
                  className={cn(onRowClick && "cursor-pointer", rowClassName?.(row.original))}
                  tabIndex={onRowClick ? 0 : undefined}
                  onClick={
                    onRowClick
                      ? (e) => {
                          // Clicks on buttons, links, switches... inside the row keep their own behavior.
                          if ((e.target as HTMLElement).closest("button, a, input, [role=switch], [role=menuitem]")) return
                          onRowClick(row.original)
                        }
                      : undefined
                  }
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === "Enter" && e.target === e.currentTarget) onRowClick(row.original)
                        }
                      : undefined
                  }
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className={cell.column.columnDef.meta?.className}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        {/* Outside the table (which may scroll sideways on a phone) so the message stays in view. */}
        {!loading && rows.length === 0 && (
          <div className="flex min-h-24 items-center justify-center px-4 py-6 text-center text-sm text-muted-foreground" data-testid="table-empty">
            {globalFilter ? emptyFiltered : empty}
          </div>
        )}
      </div>
      {!loading && data && data.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {rows.length} sur {data.length}
        </p>
      )}
    </div>
  )
}
