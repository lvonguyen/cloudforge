import '@testing-library/jest-dom'

// jsdom does not implement matchMedia — stub it for useMediaQuery and responsive components
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
})

// ReactFlow and charting surfaces rely on ResizeObserver, which jsdom does not provide.
global.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
