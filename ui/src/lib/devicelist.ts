// Device lists (pasted or CSV file) + device names.
//
// Only the kind of each line here. Server checks values (OUI digits, serial chars, EndpointID
// rules) + says what is wrong -> rules in one place (crates/api/src/enroll.rs).
// One exception: `agentEndpointId` = copy of the derivation -> picks selected devices that can
// get a certificate.

import type { Device } from './api';

/** Max devices per request (`POST /devices/bulk`). */
export const MAX_BULK = 10_000;
/** Max devices per certificate bundle. */
export const MAX_BUNDLE = 1000;
/** Max devices per bulk delete. */
export const MAX_DELETE = 1000;

/**
 * One device of a list: EndpointID (USP), or OUI + serial (USP, EndpointID
 * `os::<OUI>-<serial>`), or OUI + product class + serial (CWMP).
 */
export interface DeviceEntry {
	endpoint_id?: string;
	oui?: string;
	serial_number?: string;
	product_class?: string;
}

/** One list line + its result. */
export interface ListLine {
	/** Line number in text, from 1. */
	line: number;
	/** Line as written. */
	text: string;
	entry?: DeviceEntry;
	/** Why line cannot be read. */
	error?: string;
}

const COLUMNS = new Map<string, keyof DeviceEntry>([
	['endpoint_id', 'endpoint_id'],
	['oui', 'oui'],
	['serial', 'serial_number'],
	['serial_number', 'serial_number'],
	['product_class', 'product_class']
]);

/** Fields of a line: split on comma, semicolon or tab, else on white space. */
function fields(line: string): string[] {
	const parts = /[,;\t]/.test(line) ? line.split(/[,;\t]/) : line.split(/\s+/);
	return parts.map((f) =>
		f
			.trim()
			.replace(/^"(.*)"$/, '$1')
			.trim()
	);
}

function fromPosition(cells: string[], csv: boolean): Pick<ListLine, 'entry' | 'error'> {
	// EndpointID first: CSV line -> later columns (e.g. description) ignored.
	if (cells[0].includes('::') && (cells.length === 1 || csv))
		return { entry: { endpoint_id: cells[0] } };
	if (cells.length === 1) {
		const token = cells[0];
		const joined = /^([0-9A-Fa-f]{6})-(.+)$/.exec(token);
		if (joined) return { entry: { oui: joined[1], serial_number: joined[2] } };
		return { error: 'Not an EndpointID (os::…) or OUI-serial' };
	}
	if (cells.length === 2) return { entry: { oui: cells[0], serial_number: cells[1] } };
	if (cells.length === 3)
		return { entry: { oui: cells[0], product_class: cells[1], serial_number: cells[2] } };
	return { error: 'Too many fields' };
}

/**
 * Read a list, one device per line. Line = EndpointID (`os::B01408-B01408123456`),
 * or OUI + serial (`B01408,B01408123456`, `B01408 B01408123456` or `B01408-B01408123456`),
 * or OUI + product class + serial (CWMP device).
 * CSV line starting with EndpointID -> other columns ignored.
 * First line with only column names (`endpoint_id`, `oui`, `serial` or `serial_number`,
 * `product_class`) = header -> column order of other lines; product class -> CWMP device.
 * Blank lines + lines starting with `#` skipped.
 */
export function parseDeviceList(text: string): ListLine[] {
	const out: ListLine[] = [];
	let header: (keyof DeviceEntry)[] | null = null;
	let first = true;
	text
		.replace(/^﻿/, '')
		.split(/\r?\n/)
		.forEach((raw, i) => {
			const trimmed = raw.trim();
			if (!trimmed || trimmed.startsWith('#')) return;
			const cells = fields(trimmed);
			if (first) {
				first = false;
				const named = cells.map((c) => COLUMNS.get(c.toLowerCase()));
				if (named.every((c) => c !== undefined)) {
					header = named;
					return;
				}
			}
			const line: ListLine = { line: i + 1, text: trimmed };
			if (header) {
				const entry: DeviceEntry = {};
				header.forEach((column, j) => {
					if (cells[j]) entry[column] = cells[j];
				});
				line.entry = entry;
			} else {
				Object.assign(line, fromPosition(cells, /[,;\t]/.test(trimmed)));
			}
			out.push(line);
		});
	return out;
}

/** Display name of an entry. */
export function entryLabel(e: DeviceEntry): string {
	if (e.endpoint_id) return e.endpoint_id;
	if (e.product_class !== undefined) return [e.oui, e.product_class, e.serial_number].join(' / ');
	return `${e.oui ?? ''}-${e.serial_number ?? ''}`;
}

/**
 * Agent EndpointID of a non-retired device: USP -> own; CWMP -> `os::<OUI>-<serial>`
 * (copy of server rule). None -> null.
 */
export function agentEndpointId(d: Device): string | null {
	if (d.status === 'retired') return null;
	if (d.protocol === 'usp') return d.endpoint_id;
	const oui = d.oui ?? '';
	const serial = d.serial_number ?? '';
	if (!/^[0-9A-Fa-f]{6}$/.test(oui) || !/^[A-Za-z0-9._:@~-]{1,200}$/.test(serial)) return null;
	return `os::${oui.toUpperCase()}-${serial}`;
}
