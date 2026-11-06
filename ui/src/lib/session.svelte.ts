import type { Me } from './api';

/** Logged-in caller, set by the layout. Pages read it -> hide what the caller may not do. */
export const session = $state<{ me: Me | null }>({ me: null });
