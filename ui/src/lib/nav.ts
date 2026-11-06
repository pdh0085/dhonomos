// Redirect targets chosen by the UI.

/**
 * Page after login: path on this site only (`/devices/1`), never another site.
 * Same rule as server check of SSO return paths. Refused -> `/`:
 * - 2nd leading slash or backslash (`//evil`, `/\evil`)
 * - control chars + whitespace (browser drops tab/line break -> `/<TAB>/evil` = `//evil`)
 * - same behind `%XX` escapes
 * - any URL that resolves to another origin
 */
export function safeNext(next: string | null, origin: string = location.origin): string {
	if (!next || next.length > 2048 || !next.startsWith('/') || next.startsWith('//')) return '/';
	if (/[\\\s\u0000-\u001f\u007f-\u009f]/.test(next)) return '/';
	let decoded: string;
	try {
		decoded = decodeURIComponent(next);
	} catch {
		return '/';
	}
	if (decoded.startsWith('//') || /[\\\u0000-\u001f\u007f-\u009f]/.test(decoded)) return '/';
	try {
		if (new URL(next, origin).origin !== origin) return '/';
	} catch {
		return '/';
	}
	return next;
}
