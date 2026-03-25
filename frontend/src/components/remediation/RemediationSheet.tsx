import { Sheet, SheetContent } from '@/components/ui/sheet'
import { TicketViewportContent } from './TicketViewportContent'

interface RemediationSheetProps {
  findingId: string
  ticketId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function RemediationSheet({ findingId, ticketId, open, onOpenChange }: RemediationSheetProps) {
  void ticketId // kept for future deep-link support
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg flex flex-col p-0">
        <TicketViewportContent findingId={findingId} className="flex flex-col h-full" />
      </SheetContent>
    </Sheet>
  )
}
