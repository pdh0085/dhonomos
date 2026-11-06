// WireGuard page helpers (ADR-110).
import { ApiError, type WgStateCounts } from './api';
import { m } from './messages';

/** Seconds since `iso`; null -> Infinity. */
function age(iso: string | null | undefined): number {
	if (!iso) return Infinity;
	return Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
}

/** Dot colour of hub last contact: green < 2 min, amber < 10 min, red older or never. */
export function hubDot(lastSeen: string | null): string {
	const s = age(lastSeen);
	return s < 120 ? 'bg-green-500' : s < 600 ? 'bg-amber-500' : 'bg-red-500';
}

/**
 * Tunnel state thresholds in s = server values (`crates/wireguard` `health`,
 * also `thresholds` in `GET /wireguard/summary`).
 */
export const WG_THRESHOLDS = { connected_secs: 180, stale_secs: 900, hub_silent_secs: 300 };

/** Member tunnel state, as seen from its hub. */
export type WgState = 'connected' | 'idle' | 'stale' | 'never' | 'unknown';

/** Display order of states. */
export const WG_STATES: WgState[] = ['connected', 'idle', 'stale', 'never', 'unknown'];

/** Hub silent > threshold (or never heard) -> nothing known. */
export function hubSilent(lastSeen: string | null | undefined): boolean {
	return age(lastSeen) > WG_THRESHOLDS.hub_silent_secs;
}

/** State of a handshake `secs` old (null = never); hub heard. */
export function handshakeAgeState(secs: number | null): Exclude<WgState, 'unknown'> {
	if (secs === null) return 'never';
	if (secs < WG_THRESHOLDS.connected_secs) return 'connected';
	return secs <= WG_THRESHOLDS.stale_secs ? 'idle' : 'stale';
}

/** Member state from latest handshake + hub last contact. */
export function tunnelState(
	latest: string | null | undefined,
	hubLastSeen: string | null | undefined
): WgState {
	if (hubSilent(hubLastSeen)) return 'unknown';
	return handshakeAgeState(latest ? age(latest) : null);
}

export const stateDot: Record<WgState, string> = {
	connected: 'bg-green-500',
	idle: 'bg-amber-500',
	stale: 'bg-red-500',
	never: 'bg-slate-300',
	unknown: 'bg-slate-300'
};

export const stateText: Record<WgState, string> = {
	connected: 'text-green-700',
	idle: 'text-amber-700',
	stale: 'text-red-700',
	never: 'text-slate-500',
	unknown: 'text-slate-500'
};

/** States with members in `counts` (one or more, summed), in display order. */
export function stateParts(...counts: WgStateCounts[]): { state: WgState; n: number }[] {
	return WG_STATES.map((state) => ({
		state,
		n: counts.reduce((sum, c) => sum + c[state], 0)
	})).filter((p) => p.n > 0);
}

/** Dot colour of member latest handshake: green connected, amber idle, red stale, grey never. */
export function handshakeDot(latest: string | null | undefined): string {
	return stateDot[handshakeAgeState(latest ? age(latest) : null)];
}

/** Badge colours of device member states. */
export const deviceStateColor: Record<string, string> = {
	applied: 'bg-green-100 text-green-900',
	pending: 'bg-slate-100 text-slate-700',
	blocked: 'bg-amber-100 text-amber-900',
	unsupported: 'bg-slate-200 text-slate-800',
	error: 'bg-red-100 text-red-900'
};

export const shortKey = (key: string) => `${key.slice(0, 8)}…`;

/** Server QR code -> image source. SVG never inserted as markup. */
export function qrSource(svg: string): string {
	try {
		return `data:image/svg+xml;base64,${btoa(svg)}`;
	} catch {
		return '';
	}
}

/** Message of a failed call, for inline display. */
export function errorText(e: unknown): string {
	if (e instanceof ApiError && e.status === 0) return m.errors.network;
	return e instanceof Error ? e.message : String(e);
}
