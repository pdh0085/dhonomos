// REST API client (/api/v1). Optional bearer token -> localStorage.

export interface Device {
	id: string;
	protocol: string;
	oui: string | null;
	product_class: string;
	serial_number: string | null;
	endpoint_id: string | null;
	manufacturer: string | null;
	model_name: string | null;
	software_version: string | null;
	hardware_version: string | null;
	data_model: string | null;
	connection_request_url: string | null;
	status: string;
	tags: string[];
	first_seen_at: string;
	last_contact_at: string | null;
	last_boot_at: string | null;
	last_remote_addr: string | null;
	attributes: Record<string, string>;
	usp_ws_url: string | null;
	/** XMPP session start; null = none (ADR-104). */
	xmpp_connected_at: string | null;
	/** Full JID of that session; null = none, or API process runs no XMPP server. */
	xmpp_jid: string | null;
	/** UDP CR address of the device (STUN, ADR-040). */
	udp_cr_address: string | null;
	udp_cr_seen_at: string | null;
	/** Last wake of the device (any outcome). */
	last_wake_at: string | null;
	/** Wake channel (`xmpp`, `http`, `udp`, `usp`); null = nothing sent. */
	last_wake_method: string | null;
	last_wake_outcome: string | null;
}

/** One distinct value of a device column + count of matching devices. */
export interface FacetValue {
	value: string;
	count: number;
	/** OUIs only: manufacturer most of these devices report. */
	manufacturer?: string;
}

/** Device list filter values (`GET /devices/facets`), sorted by value. */
export interface DeviceFacets {
	oui: FacetValue[];
	product_class: FacetValue[];
	model_name: FacetValue[];
}

export interface SupportedCommand {
	name: string;
	type: string;
	inputs: string[];
	outputs: string[];
}

export interface SupportedModel {
	fingerprint: string;
	learned_at: string;
	objects: { path: string; commands: SupportedCommand[] }[];
}

export interface Preset {
	name: string;
	/** Absent = enabled. */
	enabled?: boolean;
	when: {
		events?: string[];
		oui?: string | null;
		product_class?: string | null;
		software_version?: string | null;
		tags?: string[];
		new_device?: boolean | null;
		attributes?: Record<string, string>;
	};
	once: boolean;
	priority: number;
	run?: { kind: string; payload?: unknown }[];
	script?: string;
	script_source?: string;
	args?: Record<string, string>;
}

/** Preset + where stored; `revision` null = preset from the file. */
export interface StoredPreset {
	name: string;
	enabled: boolean;
	revision: number | null;
	updated_by: string | null;
	updated_at: string | null;
	definition: Preset;
}

export interface PresetRevision {
	revision: number;
	enabled: boolean;
	deleted: boolean;
	definition: Preset | null;
	changed_by: string | null;
	changed_at: string;
}

export interface ScriptTrace {
	preset: string;
	script: string;
	error: string | null;
	duration_ms: number;
	tasks: string[];
	tags_added: string[];
	tags_removed: string[];
	virtual: [string, string | null][];
	logs: string[];
	reads: [string, string | null][];
	declared: [string, string][];
}

export interface DryRunItem {
	preset: string;
	index: number;
	kind: string;
	payload: unknown;
	priority: number;
	once: boolean;
	would_queue: boolean;
	script: boolean;
}

export interface AttributeImport {
	dry_run: boolean;
	rows: number;
	matched: number;
	updated: number;
	unknown: string[];
	unknown_count: number;
	ambiguous: string[];
	invalid: { line: number; error: string }[];
	invalid_count: number;
}

export interface DeviceFilter {
	protocol?: string;
	oui?: string;
	product_class?: string;
	software_version?: string[];
	tags?: string[];
	attributes?: Record<string, string>;
	/** Filter expression, resolved at job start. */
	expression?: string;
}

export type JobCounts = Record<
	'queued' | 'dispatched' | 'verifying' | 'succeeded' | 'failed' | 'cancelled',
	number
>;

export interface Job {
	id: string;
	name: string;
	target: DeviceFilter;
	task: { kind: string; payload: unknown };
	policy: Record<string, unknown>;
	state: string;
	stage: number;
	reason: string | null;
	total: number;
	created_at: string;
	started_at: string | null;
	finished_at: string | null;
	counts: JobCounts;
	stage_counts: JobCounts;
	stages?: number[];
	stage_limit?: number;
}

export interface JobMember {
	device_id: string;
	device: string | null;
	rank: number;
	state: string;
	task_id: string | null;
	error: string | null;
	finished_at: string | null;
}

export interface DeviceMetric {
	path: string;
	last_ts: string;
	last_value: number;
}

export interface SeriesPoint {
	ts: string;
	avg: number;
	min: number;
	max: number;
	count: number;
}

export interface ConfigBackup {
	id: string;
	device_id: string;
	label: string;
	count: number;
	created_at: string;
}

export interface BackupDiff {
	changed: { path: string; backup: string; current: string | null }[];
	missing: string[];
	unchanged: number;
}

export interface Alarm {
	id: string;
	device_id: string;
	device: string | null;
	rule: string;
	severity: string;
	state: string;
	message: string;
	raised_at: string;
	cleared_at: string | null;
	acked_at: string | null;
	acked_by: string | null;
	silenced_by: string | null;
}

export interface DeviceFilter {
	protocol?: string;
	oui?: string;
	product_class?: string;
	software_version?: string[];
	tags?: string[];
	device_ids?: string[];
}

export interface Silence {
	id: string;
	rule: string | null;
	devices: DeviceFilter;
	starts_at: string;
	ends_at: string;
	state: 'pending' | 'active' | 'ended';
	comment: string;
	created_by: string | null;
	created_at: string;
}

export interface AlarmRule {
	name: string;
	severity: string;
	/** Target devices: fixed conditions as in job targets (empty = all active devices). */
	devices: DeviceFilter & { device_ids?: string[]; status?: string };
	/** One of `{offline_minutes}`, `{wg_handshake_minutes}`, `{metric, above?, below?}` or
	 * `{event, detail?, count, within_minutes}`. */
	when: {
		offline_minutes?: number;
		wg_handshake_minutes?: number;
		metric?: string;
		above?: number | null;
		below?: number | null;
		event?: string;
		detail?: unknown;
		count?: number;
		within_minutes?: number;
	};
}

/** Alarm rules + source (`GET /settings/alarm-rules`, admin). */
export interface AlarmRuleSettings {
	/** `file`: server --alarms file (read-only); `web`: stored from the web; `none`. */
	source: 'file' | 'web' | 'none';
	path: string | null;
	yaml: string | null;
	editable: boolean;
	/** Rules the server evaluates. */
	rules: { alarms: AlarmRule[]; storm_threshold: number };
	updated_by: string | null;
	updated_at: string | null;
}

/** One version of web-stored alarm rules. */
export interface AlarmRuleVersion {
	yaml: string | null;
	actor: string | null;
	at: string;
}

export interface WifiView {
	radios: {
		id: string;
		band: string | null;
		channel: number | null;
		bandwidth: string | null;
		noise_dbm: number | null;
		status: string | null;
	}[];
	networks: {
		ssid: string | null;
		bssid: string | null;
		channel?: number | null;
		security: string | null;
		stations: { mac: string | null; signal_dbm: number | null; down_kbps: number | null }[];
	}[];
	neighbor_scan: {
		at: string;
		neighbors:
			| {
					ssid: string | null;
					bssid: string | null;
					channel: number | null;
					signal_dbm: number | null;
					band: string | null;
			  }[]
			| null;
	} | null;
}

/** Devices an account or key may see + act on; all conditions must hold. */
export interface DeviceScope {
	tags?: string[];
	attributes?: Record<string, string>;
	protocol?: string;
	oui?: string;
	product_class?: string;
}

export interface Me {
	name: string;
	role: 'admin' | 'operator' | 'viewer';
	via: string;
	scope?: DeviceScope | null;
	/** Login session of an account with 2FA on. */
	totp_enabled?: boolean;
	/** Account must have 2FA -> until then, session may only enroll. */
	totp_required?: boolean;
	/** Account can set up 2FA: local account + server with secrets key. */
	totp_available?: boolean;
}

/** Authenticator app secret; not active until a code from it is confirmed. */
export interface TotpSetup {
	secret: string;
	otpauth_uri: string;
	qr_svg: string;
}

/** Scope as text: `tag:east, region=busan, protocol:cwmp` (empty = every device). */
export function scopeText(scope: DeviceScope | null | undefined): string {
	if (!scope) return '';
	return [
		...(scope.tags ?? []).map((t) => `tag:${t}`),
		...Object.entries(scope.attributes ?? {}).map(([k, v]) => `${k}=${v}`),
		...(['protocol', 'oui', 'product_class'] as const)
			.filter((k) => scope[k])
			.map((k) => `${k}:${scope[k]}`)
	].join(', ');
}

/** Parse `scopeText` output; empty text -> `null` (every device). */
export function parseScope(text: string): DeviceScope | null {
	const scope: DeviceScope = {};
	for (const part of text.split(',').map((p) => p.trim())) {
		if (!part) continue;
		const colon = part.indexOf(':');
		const eq = part.indexOf('=');
		if (eq > 0 && (colon < 0 || eq < colon)) {
			(scope.attributes ??= {})[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
			continue;
		}
		const key = colon > 0 ? part.slice(0, colon).trim() : '';
		const value = part.slice(colon + 1).trim();
		if (key === 'tag') (scope.tags ??= []).push(value);
		else if (key === 'protocol' || key === 'oui' || key === 'product_class') scope[key] = value;
		else
			throw new Error(
				`Scope: cannot read "${part}" (use tag:x, key=value, protocol:, oui:, product_class:)`
			);
	}
	return Object.keys(scope).length ? scope : null;
}

export interface UserAccount {
	id: string;
	username: string;
	role: string;
	disabled: boolean;
	created_at: string;
	last_login_at: string | null;
	scope: DeviceScope | null;
	totp_enabled: boolean;
}

export interface ApiKeyInfo {
	id: string;
	name: string;
	prefix: string;
	role: string;
	created_by: string | null;
	created_at: string;
	last_used_at: string | null;
	revoked_at: string | null;
	scope: DeviceScope | null;
}

/** Server option, value in use (`GET /settings/server`). */
export interface ServerSetting {
	key: string;
	flag: string;
	env: string;
	group: string;
	category: 'bootstrap' | 'runtime' | 'security' | 'secret';
	help: string;
	source: 'cli' | 'env' | 'default' | 'unset' | 'web';
	is_set: boolean;
	/** Null for secrets + when unset; passwords in URLs = `****`. */
	value: string | null;
	/** Web edit kind. */
	kind: 'bool' | 'list' | 'text';
	/** Runtime option not set by the server config. */
	editable: boolean;
	/** Why a runtime option is locked for the web. */
	locked_reason: string | null;
	/** Web-stored value (masked like `value`); ignored when locked. */
	web_value: string | string[] | null;
}

/** One web change of a runtime option; `new` null = reset. */
export interface ServerSettingChange {
	old: string | string[] | null;
	new: string | string[] | null;
	actor: string | null;
	at: string;
}

export interface Overview {
	active: number;
	online: { m15: number; h1: number; d1: number };
	by_protocol: Record<string, number>;
	by_status: Record<string, number>;
	sessions_per_minute: { ts: string; n: number }[];
	tasks: Record<string, number>;
	jobs_running: number;
	versions: { version: string; n: number }[];
	alarms: Record<string, number>;
}

export interface Parameter {
	path: string;
	value: string | null;
	type: string | null;
	writable: boolean | null;
	updated_at: string;
}

export interface Task {
	id: string;
	kind: string;
	payload: unknown;
	state: string;
	attempts: number;
	max_attempts: number;
	result: unknown;
	error: string | null;
	created_at: string;
	created_by: string | null;
	job_id: string | null;
	connection_request?: string;
	trace?: TaskStep[];
}

/** One step of a task (queued, dispatched, waiting, retry, succeeded, failed, ...). */
export interface TaskStep {
	at: string;
	step: string;
	attempt: number;
	detail?: string;
}

/** Certificate issued to a USP Agent (no private key). */
export interface AgentCertificate {
	id: string;
	device_id: string;
	serial: string;
	sha256: string;
	not_after: string;
	from_csr: boolean;
	issued_by: string | null;
	issued_at: string;
	state: 'valid' | 'expired' | 'revoked';
	revoked_at: string | null;
	revoked_by: string | null;
	revoke_reason: string | null;
	device: string | null;
}

/** Result of `POST /devices/bulk` for one entry (dry run: would-be result). */
export interface BulkResult {
	index: number;
	status: 'added' | 'exists' | 'invalid';
	protocol?: 'usp' | 'cwmp';
	endpoint_id?: string;
	oui?: string;
	product_class?: string;
	serial_number?: string;
	device_id?: string;
	device_status?: string;
	error?: string;
}

export interface BulkReport {
	dry_run: boolean;
	total: number;
	added: number;
	exists: number;
	invalid: number;
	results: BulkResult[];
}

/** Certificate bundle targets: any mix, max 1,000 devices. */
export interface BundleRequest {
	device_ids?: string[];
	targets?: { endpoint_id?: string; oui?: string; serial_number?: string }[];
	filter?: string;
	/** Add Agents of `targets` not yet in the list (with `tags`). */
	create_missing?: boolean;
	tags?: string[];
	days: number;
	password: string;
}

/** Bundle result, from the answer headers. */
export interface BundleResult {
	/** File name of the saved zip. */
	name: string;
	/** Certificates in the zip. */
	issued: number;
	/** Devices added to the list for them. */
	created: number;
}

/** Counts removed by a bulk device delete. */
export interface DeleteResult {
	deleted: number;
	certificates_revoked: number;
	files: number;
}

export interface IssuedCertificate {
	certificate: string;
	private_key: string | null;
	/** Certificate + key, ready to install (`obuspa -a`); null with a CSR. */
	client_pem: string | null;
	ca_certificate: string;
	serial: string;
	sha256: string;
	not_after: string;
}

export interface StoredFile {
	id: string;
	name: string;
	file_type: string;
	size_bytes: number;
	sha256: string;
	version: string | null;
	created_at: string;
}

export interface AuditEntry {
	id: number;
	actor: string;
	action: string;
	target_type: string;
	target_id: string | null;
	detail: Record<string, unknown>;
	occurred_at: string;
}

export interface DeviceEvent {
	id: number;
	kind: string;
	detail: Record<string, unknown>;
	occurred_at: string;
}

/** WireGuard hub (ADR-110): endpoint run by hub process `dhonomos-wg-hub`. */
export interface WgHub {
	id: string;
	name: string;
	endpoint_host: string;
	/** Null until the hub process reports it. */
	public_key: string | null;
	networks: number;
	token_prefix: string | null;
	token_created_at: string | null;
	last_seen_at: string | null;
	last_seen_ip: string | null;
	version: string | null;
	state_revision: number;
	created_at: string;
	updated_at: string;
}

/** WireGuard overlay network on a hub. */
export interface WgNetwork {
	id: string;
	hub: { id: string; name: string; endpoint_host: string; public_key: string | null };
	name: string;
	ipv4_prefix: string;
	hub_address: string;
	listen_port: number;
	mtu: number;
	persistent_keepalive: number;
	/** Member counts visible to the caller. */
	members: { device: number; client: number; revoked: number };
	created_at: string;
	updated_at: string;
}

/** Member state, last hub report. */
export interface WgHubStatus {
	endpoint: string | null;
	latest_handshake: string | null;
	rx_bytes: number;
	tx_bytes: number;
	reported_at: string;
}

/** Progress of the CPE of a device member. */
export interface WgDeviceStatus {
	state: 'pending' | 'applied' | 'blocked' | 'unsupported' | 'error' | string;
	detail: string | null;
	checked_at: string | null;
}

export interface WgMember {
	id: string;
	network_id: string;
	kind: 'device' | 'client';
	name: string;
	device_id: string | null;
	/** Clients: owning account; null = server client. */
	user_id: string | null;
	public_key: string | null;
	key_mode: string | null;
	/** Member has a PSK (key itself shown only at creation). */
	preshared_key_enabled: boolean;
	address: string;
	site_prefixes: { prefix: string; description: string }[];
	revoked_at: string | null;
	revoked_reason: string | null;
	hub_status: WgHubStatus | null;
	/** Null for clients. */
	device_status: WgDeviceStatus | null;
	/** Device members: key rotation request time; null = none open. */
	rotate_requested_at: string | null;
	created_at: string;
	updated_at: string;
}

/**
 * Device report of its tunnel in a network (stored `Device.WireGuard.` rows, network alias).
 * Value missing from the snapshot -> null.
 */
export interface WgDeviceSide {
	tunnel_status: string | null;
	interface_status: string | null;
	/** Seconds since last handshake at read time (`read_at`); 0 = never. */
	last_handshake_secs: number | null;
	bytes_sent: number | null;
	bytes_received: number | null;
	read_at: string;
}

/** Device member in a device WireGuard view: of the device itself or of its twin. */
export interface WgDeviceMember extends WgMember {
	network_name: string;
	/** Null = own member of the device; else the other record (CWMP or USP) of the same CPE. */
	via_twin: { device_id: string; protocol: 'cwmp' | 'usp' | string } | null;
	/**
	 * Report of the owning record (device or `via_twin`).
	 * Null = its snapshot has no Tunnel with the network alias.
	 */
	device_side: WgDeviceSide | null;
}

/** Live member count per tunnel state. */
export interface WgStateCounts {
	total: number;
	connected: number;
	idle: number;
	stale: number;
	never: number;
	/** Hub of the member is silent. */
	unknown: number;
}

/** Tunnel health of members visible to the caller: total + per network (by name). */
export interface WgSummary {
	thresholds: { connected_secs: number; stale_secs: number; hub_silent_secs: number };
	totals: { device: WgStateCounts; client: WgStateCounts };
	networks: {
		id: string;
		name: string;
		hub_id: string;
		hub_name: string;
		device: WgStateCounts;
		client: WgStateCounts;
	}[];
}

/**
 * Answer of member create / re-key: client with server-made key pair -> private key,
 * config with it + QR code; PSK made for the request.
 * Exists only here (never stored by the UI).
 */
export interface WgSecretAnswer extends WgMember {
	private_key: string | null;
	config: string | null;
	config_filename: string | null;
	qr_svg: string | null;
	preshared_key: string | null;
}

export type WgNewMember =
	| { kind: 'client'; name: string; user_id?: string | null; preshared_key_enabled?: boolean }
	| {
			kind: 'device';
			device_id: string;
			name?: string;
			key_mode?: 'device' | 'server';
			preshared_key_enabled?: boolean;
			site_prefixes?: { prefix: string; description?: string }[];
	  };

export class ApiError extends Error {
	constructor(
		public status: number,
		message: string,
		/** JSON body of the answer, for machine-readable parts e.g. `totp_required`. */
		public data: Record<string, unknown> = {}
	) {
		super(message);
	}
}

const TOKEN_KEY = 'dhonomos.apiToken';

export function getToken(): string {
	try {
		return localStorage.getItem(TOKEN_KEY) ?? '';
	} catch {
		return '';
	}
}

export function setToken(token: string) {
	try {
		localStorage.setItem(TOKEN_KEY, token);
	} catch {
		// Storage unavailable -> token lasts for this page only.
	}
}

async function call<T>(method: string, path: string, body?: unknown, raw?: Blob): Promise<T> {
	const headers: Record<string, string> = {};
	const token = getToken();
	if (token) headers.authorization = `Bearer ${token}`;
	if (body !== undefined) headers['content-type'] = 'application/json';
	if (raw) headers['content-type'] = raw.type || 'application/octet-stream';
	let resp: Response;
	try {
		resp = await fetch(`/api/v1${path}`, {
			method,
			headers,
			body: raw ?? (body === undefined ? undefined : JSON.stringify(body))
		});
	} catch {
		throw new ApiError(0, 'network');
	}
	if (resp.status === 204) return undefined as T;
	const data = await resp.json().catch(() => ({}));
	if (!resp.ok) throw new ApiError(resp.status, data.error ?? resp.statusText, data);
	return data as T;
}

/** Download `path` (bearer token if any) -> save as `filename`. */
export async function download(path: string, filename: string): Promise<void> {
	const headers: Record<string, string> = {};
	const token = getToken();
	if (token) headers.authorization = `Bearer ${token}`;
	const resp = await fetch(`/api/v1${path}`, { headers });
	if (!resp.ok) {
		const data = await resp.json().catch(() => ({}));
		throw new ApiError(resp.status, data.error ?? resp.statusText);
	}
	const url = URL.createObjectURL(await resp.blob());
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}

/**
 * POST `body` as JSON to `path` -> save the answer (a file) under the server name, else
 * `fallback`. Returns that name + the answer headers.
 */
export async function downloadPost(
	path: string,
	body: unknown,
	fallback: string
): Promise<{ name: string; headers: Headers }> {
	const headers: Record<string, string> = { 'content-type': 'application/json' };
	const token = getToken();
	if (token) headers.authorization = `Bearer ${token}`;
	let resp: Response;
	try {
		resp = await fetch(`/api/v1${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
	} catch {
		throw new ApiError(0, 'network');
	}
	if (!resp.ok) {
		const data = await resp.json().catch(() => ({}));
		throw new ApiError(resp.status, data.error ?? resp.statusText);
	}
	const name =
		/filename="([^"]+)"/.exec(resp.headers.get('content-disposition') ?? '')?.[1] ?? fallback;
	const url = URL.createObjectURL(await resp.blob());
	const a = document.createElement('a');
	a.href = url;
	a.download = name;
	a.click();
	URL.revokeObjectURL(url);
	return { name, headers: resp.headers };
}

export const api = {
	devices: (filters: Record<string, string> = {}, limit = 100, offset = 0) => {
		const q = new URLSearchParams({ limit: String(limit), offset: String(offset) });
		for (const [k, v] of Object.entries(filters)) if (v.trim()) q.set(k, v.trim());
		return call<{ items: Device[]; total: number }>('GET', `/devices?${q}`);
	},
	/** OUIs, product classes, model names for the device list filters. */
	deviceFacets: (filters: Record<string, string> = {}) => {
		const q = new URLSearchParams();
		for (const [k, v] of Object.entries(filters)) if (v.trim()) q.set(k, v.trim());
		return call<DeviceFacets>('GET', `/devices/facets?${q}`);
	},
	device: (id: string) => call<Device>('GET', `/devices/${id}`),
	certificates: (id: string) =>
		call<{ items: AgentCertificate[] }>('GET', `/devices/${id}/certificates`).then((r) => r.items),
	issueCertificate: (id: string, days: number, csr?: string) =>
		call<IssuedCertificate>('POST', `/devices/${id}/certificate`, { days, csr }),
	/** Issue certificates with new keys for the devices -> save as encrypted zip. */
	issueCertificateBundle: (req: BundleRequest): Promise<BundleResult> =>
		downloadPost('/certificates/bundle', req, 'usp-agent-certificates.zip').then(
			({ name, headers }) => ({
				name,
				issued: Number(headers.get('x-certificates-issued') ?? 0),
				created: Number(headers.get('x-devices-created') ?? 0)
			})
		),
	/** Add devices before they connect; `dryRun` -> only report what would happen. */
	preregisterDevices: (
		devices: {
			endpoint_id?: string;
			oui?: string;
			serial_number?: string;
			product_class?: string;
		}[],
		tags: string[],
		dryRun: boolean
	) => call<BulkReport>('POST', '/devices/bulk', { devices, tags, dry_run: dryRun }),
	revokeCertificate: (id: string, cert: string, reason: string) =>
		call<AgentCertificate>('POST', `/devices/${id}/certificates/${cert}/revoke`, { reason }),
	parameters: (id: string, prefix: string) =>
		call<{ items: Parameter[] }>(
			'GET',
			`/devices/${id}/parameters?prefix=${encodeURIComponent(prefix)}`
		).then((r) => r.items),
	tasks: (id: string) =>
		call<{ items: Task[] }>('GET', `/devices/${id}/tasks?limit=200`).then((r) => r.items),
	events: (id: string) =>
		call<{ items: DeviceEvent[] }>('GET', `/devices/${id}/events?limit=200`).then((r) => r.items),
	jobs: () => call<{ items: Job[] }>('GET', '/jobs?limit=200').then((r) => r.items),
	job: (id: string) => call<Job>('GET', `/jobs/${id}`),
	jobMembers: (id: string, state: string) =>
		call<{ items: JobMember[] }>(
			'GET',
			`/jobs/${id}/devices?state=${encodeURIComponent(state)}&limit=100`
		).then((r) => r.items),
	previewJob: (target: DeviceFilter) =>
		call<{ count: number; sample: Device[] }>('POST', '/jobs/preview', { target }),
	createJob: (job: unknown) => call<Job>('POST', '/jobs', job),
	jobAction: (id: string, action: string) => call<Job>('POST', `/jobs/${id}/${action}`),
	metrics: (id: string) =>
		call<{ items: DeviceMetric[] }>('GET', `/devices/${id}/metrics`).then((r) => r.items),
	/** `step`: bucket size in s; default = server's (~200 points). */
	series: (id: string, path: string, hours: number, step?: number) => {
		const to = new Date();
		const from = new Date(to.getTime() - hours * 3600_000);
		const q = new URLSearchParams({ path, from: from.toISOString(), to: to.toISOString() });
		if (step !== undefined) q.set('step', String(step));
		return call<{ step: number; points: SeriesPoint[] }>(
			'GET',
			`/devices/${id}/metrics/series?${q}`
		);
	},
	bulkdataUrl: (id: string) => call<{ url: string }>('GET', `/devices/${id}/bulkdata-url`),
	backups: (id: string) =>
		call<{ items: ConfigBackup[] }>('GET', `/devices/${id}/config-backups`).then((r) => r.items),
	createBackup: (id: string, label: string) =>
		call<ConfigBackup & { notes: Record<string, number> }>(
			'POST',
			`/devices/${id}/config-backups`,
			{ label }
		),
	backupDiff: (backup: string) => call<BackupDiff>('GET', `/config-backups/${backup}/diff`),
	restoreBackup: (backup: string) =>
		call<{ tasks: string[] }>('POST', `/config-backups/${backup}/restore`, {}),
	deleteBackup: (backup: string) => call<void>('DELETE', `/config-backups/${backup}`),
	configFiles: (id: string) =>
		call<{ items: StoredFile[] }>('GET', `/devices/${id}/config-files`).then((r) => r.items),
	requestConfigFile: (id: string) =>
		call<{ task_id: string; connection_request: string }>('POST', `/devices/${id}/config-files`),
	logFiles: (id: string) =>
		call<{ items: StoredFile[] }>('GET', `/devices/${id}/log-files`).then((r) => r.items),
	requestLogFile: (id: string) =>
		call<{ task_id: string; connection_request: string }>('POST', `/devices/${id}/log-files`),
	/** Save a stored file (operators only). */
	saveFile: (f: StoredFile) => download(`/files/${f.id}/content`, f.name),
	replaceDevice: (id: string, newId: string) =>
		call<{ tasks: string[] }>('POST', `/devices/${id}/replace`, { new_device_id: newId }),
	deleteDevice: (id: string) => call<void>('DELETE', `/devices/${id}`),
	/** Delete devices + all their data; `retire` -> devices in service retired first. */
	deleteDevices: (ids: string[], retire: boolean) =>
		call<DeleteResult>('POST', '/devices/delete', { device_ids: ids, retire }),
	alarms: (state: string) =>
		call<{ items: Alarm[]; active: Record<string, number> }>(
			'GET',
			`/alarms?limit=500${state ? `&state=${state}` : ''}`
		),
	ackAlarm: (id: string) => call<Alarm>('POST', `/alarms/${id}/ack`),
	presets: () => call<{ source: 'database' | 'file'; items: StoredPreset[] }>('GET', '/presets'),
	preset: (name: string) => call<StoredPreset>('GET', `/presets/${encodeURIComponent(name)}`),
	savePreset: (name: string, definition: Partial<Preset>, revision: number) =>
		call<StoredPreset>('PUT', `/presets/${encodeURIComponent(name)}`, { definition, revision }),
	deletePreset: (name: string, revision: number) =>
		call<void>('DELETE', `/presets/${encodeURIComponent(name)}?revision=${revision}`),
	presetHistory: (name: string) =>
		call<{ items: PresetRevision[] }>('GET', `/presets/${encodeURIComponent(name)}/history`).then(
			(r) => r.items
		),
	validatePreset: (definition: Partial<Preset>) =>
		call<{ ok: boolean }>('POST', '/presets/validate', definition),
	importPresets: (yaml: string, dry_run: boolean) =>
		call<{ created: string[]; updated: string[]; unchanged: string[] }>('POST', '/presets/import', {
			yaml,
			dry_run
		}),
	presetDryRun: (
		device_id: string,
		events: string[],
		new_device: boolean,
		draft?: Partial<Preset>
	) =>
		call<{ items: DryRunItem[]; scripts: ScriptTrace[] }>('POST', '/presets/dry-run', {
			device_id,
			events,
			new_device,
			draft
		}),
	alarmRules: () => call<{ items: AlarmRule[] }>('GET', '/alarm-rules').then((r) => r.items),
	alarmRuleSettings: () => call<AlarmRuleSettings>('GET', '/settings/alarm-rules'),
	setAlarmRules: (yaml: string) =>
		call<AlarmRuleSettings>('PUT', '/settings/alarm-rules', { yaml }),
	alarmRuleHistory: () =>
		call<{ items: AlarmRuleVersion[] }>('GET', '/settings/alarm-rules/history').then(
			(r) => r.items
		),
	silences: () => call<{ items: Silence[] }>('GET', '/alarm-silences').then((r) => r.items),
	createSilence: (s: {
		rule?: string;
		devices: DeviceFilter;
		duration_minutes: number;
		comment: string;
	}) => call<Silence>('POST', '/alarm-silences', s),
	endSilence: (id: string) => call<Silence>('DELETE', `/alarm-silences/${id}`),
	wifi: (id: string) => call<WifiView>('GET', `/devices/${id}/wifi`),
	me: () => call<Me>('GET', '/auth/me'),
	authConfig: () => call<{ password: boolean; sso: boolean }>('GET', '/auth/config'),
	login: (username: string, password: string, totp?: string) =>
		call<{ username: string; role: string }>('POST', '/auth/login', { username, password, totp }),
	logout: () => call<void>('POST', '/auth/logout'),
	/** New secret; `code` needed when 2FA is on already. */
	totpSetup: (code?: string) => call<TotpSetup>('POST', '/auth/totp/setup', { code }),
	totpEnable: (code: string) =>
		call<{ recovery_codes: string[] }>('POST', '/auth/totp/enable', { code }),
	totpDisable: (password: string, code: string) =>
		call<void>('POST', '/auth/totp/disable', { password, code }),
	totpRecoveryCodes: (code: string) =>
		call<{ recovery_codes: string[] }>('POST', '/auth/totp/recovery-codes', { code }),
	resetUserTotp: (id: string) => call<void>('DELETE', `/users/${id}/totp`),
	users: () => call<{ items: UserAccount[] }>('GET', '/users').then((r) => r.items),
	createUser: (username: string, password: string, role: string, scope: DeviceScope | null) =>
		call<UserAccount>('POST', '/users', { username, password, role, scope }),
	updateUser: (
		id: string,
		change: { role?: string; disabled?: boolean; password?: string; scope?: DeviceScope | null }
	) => call<UserAccount>('PATCH', `/users/${id}`, change),
	deleteUser: (id: string) => call<void>('DELETE', `/users/${id}`),
	apiKeys: () => call<{ items: ApiKeyInfo[] }>('GET', '/api-keys').then((r) => r.items),
	createApiKey: (name: string, role: string, scope: DeviceScope | null) =>
		call<ApiKeyInfo & { key: string }>('POST', '/api-keys', { name, role, scope }),
	revokeApiKey: (id: string) => call<void>('DELETE', `/api-keys/${id}`),
	serverSettings: () =>
		call<{ items: ServerSetting[] }>('GET', '/settings/server').then((r) => r.items),
	setServerSetting: (key: string, value: string | string[]) =>
		call<ServerSetting>('PUT', `/settings/server/${encodeURIComponent(key)}`, { value }),
	resetServerSetting: (key: string) =>
		call<void>('DELETE', `/settings/server/${encodeURIComponent(key)}`),
	serverSettingHistory: (key: string) =>
		call<{ items: ServerSettingChange[] }>(
			'GET',
			`/settings/server/${encodeURIComponent(key)}/history`
		).then((r) => r.items),
	overview: () => call<Overview>('GET', '/overview'),
	supportedModel: (id: string) => call<SupportedModel>('GET', `/devices/${id}/supported-model`),
	/** `refreshing`: Agent connected, read now; `queued`: read when it connects. */
	refreshDataModel: (id: string) =>
		call<{ status: 'refreshing' | 'queued' }>('POST', `/devices/${id}/data-model/refresh`),
	createTask: (id: string, task: { kind: string; payload?: unknown }) =>
		call<Task>('POST', `/devices/${id}/tasks`, task),
	cancelTask: (taskId: string) => call<void>('DELETE', `/tasks/${taskId}`),
	task: (taskId: string) => call<Task>('GET', `/tasks/${taskId}`),
	wake: (id: string) =>
		call<{ connection_request: string }>('POST', `/devices/${id}/connection-request`),
	setStatus: (id: string, status: string) => call<Device>('PATCH', `/devices/${id}`, { status }),
	importAttributes: (file: File, dryRun: boolean) =>
		call<AttributeImport>(
			'POST',
			`/devices/attributes/import${dryRun ? '?dry_run=true' : ''}`,
			undefined,
			new Blob([file], { type: 'text/csv' })
		),
	updateDevice: (
		id: string,
		change: { tags?: string[]; attributes?: Record<string, string | null>; usp_ws_url?: string }
	) => call<Device>('PATCH', `/devices/${id}`, change),
	files: () => call<{ items: StoredFile[] }>('GET', '/files').then((r) => r.items),
	uploadFile: (file: File, fileType: string, version: string) => {
		const q = new URLSearchParams({ name: file.name, file_type: fileType });
		if (version) q.set('version', version);
		return call<StoredFile>('PUT', `/files?${q}`, undefined, file);
	},
	deleteFile: (id: string) => call<void>('DELETE', `/files/${id}`),
	wgSummary: () => call<WgSummary>('GET', '/wireguard/summary'),
	wgHubs: () => call<{ items: WgHub[] }>('GET', '/wireguard/hubs').then((r) => r.items),
	createWgHub: (name: string, endpoint_host: string) =>
		call<WgHub>('POST', '/wireguard/hubs', { name, endpoint_host }),
	/** New hub token, shown only in this answer; replaces the current one at once. */
	issueWgHubToken: (id: string) =>
		call<{ token: string; token_prefix: string; hub: WgHub }>(
			'POST',
			`/wireguard/hubs/${id}/token`
		),
	revokeWgHubToken: (id: string) => call<void>('DELETE', `/wireguard/hubs/${id}/token`),
	wgNetworks: () => call<{ items: WgNetwork[] }>('GET', '/wireguard/networks').then((r) => r.items),
	wgNetwork: (id: string) => call<WgNetwork>('GET', `/wireguard/networks/${id}`),
	createWgNetwork: (n: {
		hub_id: string;
		name: string;
		prefix_len?: number;
		ipv4_prefix?: string;
		listen_port?: number;
		mtu?: number;
	}) => call<WgNetwork>('POST', '/wireguard/networks', n),
	wgMembers: (network: string, includeRevoked: boolean, limit = 1000, offset = 0) =>
		call<{ items: WgMember[]; total: number }>(
			'GET',
			`/wireguard/networks/${network}/members?include_revoked=${includeRevoked}&limit=${limit}&offset=${offset}`
		),
	/** Live device members of a device + its twin, by network name. */
	deviceWireguard: (deviceId: string) =>
		call<{ items: WgDeviceMember[] }>('GET', `/devices/${deviceId}/wireguard`).then((r) => r.items),
	createWgMember: (network: string, member: WgNewMember) =>
		call<WgSecretAnswer>('POST', `/wireguard/networks/${network}/members`, member),
	/** Client config without the private key. */
	wgMemberConfig: (id: string) =>
		call<{ config: string; config_filename: string }>('GET', `/wireguard/members/${id}/config`),
	rekeyWgMember: (id: string) => call<WgSecretAnswer>('POST', `/wireguard/members/${id}/rekey`),
	/** Device member -> new key at next run of its device. */
	rotateWgMemberKey: (id: string) => call<WgMember>('POST', `/wireguard/members/${id}/rotate-key`),
	/** All live device members of the network -> new key (admins). */
	rotateWgNetworkKeys: (networkId: string) =>
		call<{ requested: number }>('POST', `/wireguard/networks/${networkId}/rotate-keys`),
	revokeWgMember: (id: string, reason?: string) =>
		call<WgMember>('POST', `/wireguard/members/${id}/revoke`, { reason }),
	updateWgMember: (
		id: string,
		change: { name?: string; site_prefixes?: { prefix: string; description?: string }[] }
	) => call<WgMember>('PATCH', `/wireguard/members/${id}`, change),
	audit: (filters: Record<string, string> = {}, before?: number) => {
		const q = new URLSearchParams({ limit: '100' });
		for (const [k, v] of Object.entries(filters)) if (v.trim()) q.set(k, v.trim());
		if (before !== undefined) q.set('before', String(before));
		return call<{ items: AuditEntry[] }>('GET', `/audit?${q}`).then((r) => r.items);
	}
};

/** Save `text` as file `filename`, not kept anywhere. */
export function saveText(text: string, filename: string) {
	const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}

export function bytes(n: number): string {
	if (n < 1024) return `${n} B`;
	if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
	if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
	return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

/** Rate in bit/s, decimal units. */
export function bitRate(bps: number): string {
	if (bps < 1000) return `${Math.round(bps)} bit/s`;
	if (bps < 1000 ** 2) return `${(bps / 1000).toFixed(1)} kbit/s`;
	if (bps < 1000 ** 3) return `${(bps / 1000 ** 2).toFixed(1)} Mbit/s`;
	return `${(bps / 1000 ** 3).toFixed(2)} Gbit/s`;
}

export function ago(iso: string | null | undefined, never = '—'): string {
	if (!iso) return never;
	const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
	if (s < 60) return `${s}s ago`;
	if (s < 3600) return `${Math.floor(s / 60)}m ago`;
	if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
	return `${Math.floor(s / 86400)}d ago`;
}
