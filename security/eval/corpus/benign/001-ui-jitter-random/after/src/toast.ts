export function toastDelay(): number {
  // Stagger simultaneous toasts so they do not animate in lockstep.
  return 300 + Math.random() * 120;
}
