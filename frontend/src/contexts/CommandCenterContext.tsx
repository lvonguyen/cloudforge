import {
  createContext,
  useContext,
  useReducer,
  useMemo,
  type ReactNode,
  type Dispatch,
} from 'react'
import type { Finding } from '@/types/compliance'
import type { AttackPath } from '@/types/attack-path'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SelectedEntity =
  | { type: 'finding'; data: Finding }
  | { type: 'attack-path'; data: AttackPath }
  | null

type Action =
  | { type: 'SELECT_ENTITY'; payload: SelectedEntity }
  | { type: 'TOGGLE_LAYER'; payload: { layerId: string; enabled: boolean } }
  | { type: 'SET_LAYERS'; payload: Record<string, boolean> }
  | { type: 'SELECT_PATH'; payload: string | null }
  | { type: 'TOGGLE_LEFT_PANEL' }

interface State {
  selectedEntity: SelectedEntity
  activeLayers: Record<string, boolean>
  selectedPathId: string | null
  leftPanelOpen: boolean
}

// ---------------------------------------------------------------------------
// Initial state — Critical + High severities on, production only
// ---------------------------------------------------------------------------

const INITIAL_LAYERS: Record<string, boolean> = {
  'severity:CRITICAL': true,
  'severity:HIGH': true,
  'severity:MEDIUM': false,
  'severity:LOW': false,
  'provider:aws': true,
  'provider:azure': true,
  'provider:gcp': true,
  'environment:production': true,
  'environment:staging': false,
  'environment:development': false,
  'environment:sandbox': false,
  'remediation:pending': true,
  'remediation:in_progress': true,
  'remediation:completed': false,
  'remediation:failed': false,
}

const INITIAL_STATE: State = {
  selectedEntity: null,
  activeLayers: INITIAL_LAYERS,
  selectedPathId: null,
  leftPanelOpen: true,
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'SELECT_ENTITY':
      return { ...state, selectedEntity: action.payload }
    case 'TOGGLE_LAYER':
      return {
        ...state,
        activeLayers: {
          ...state.activeLayers,
          [action.payload.layerId]: action.payload.enabled,
        },
      }
    case 'SET_LAYERS':
      return { ...state, activeLayers: { ...state.activeLayers, ...action.payload } }
    case 'SELECT_PATH':
      return { ...state, selectedPathId: action.payload }
    case 'TOGGLE_LEFT_PANEL':
      return { ...state, leftPanelOpen: !state.leftPanelOpen }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------

interface ContextValue {
  state: State
  dispatch: Dispatch<Action>
  showDetailPanel: boolean
}

const Ctx = createContext<ContextValue | null>(null)

export function CommandCenterProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, INITIAL_STATE)
  const showDetailPanel = state.selectedEntity !== null

  const value = useMemo(
    () => ({ state, dispatch, showDetailPanel }),
    [state, showDetailPanel],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useCommandCenter() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useCommandCenter must be used within CommandCenterProvider')
  return ctx
}

// ---------------------------------------------------------------------------
// Layer key helpers — parseable flat keys for the activeLayers map
// ---------------------------------------------------------------------------

export function parseLayerKey(key: string): { group: string; value: string } {
  const idx = key.indexOf(':')
  return { group: key.slice(0, idx), value: key.slice(idx + 1) }
}

export function layerKey(group: string, value: string): string {
  return `${group}:${value}`
}
