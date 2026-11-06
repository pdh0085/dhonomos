<script lang="ts">
	import {
		ago,
		api,
		type AlarmRule,
		type AlarmRuleSettings,
		type AlarmRuleVersion
	} from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';

	const admin = $derived(session.me?.role === 'admin');

	let rules = $state<AlarmRule[] | null>(null);
	// Admins only: rule source + YAML.
	let settings = $state<AlarmRuleSettings | null>(null);
	let error = $state<unknown>(null);

	let editing = $state(false);
	let draft = $state('');
	let saveError = $state('');
	let saving = $state(false);

	let historyOpen = $state(false);
	// Null while loading.
	let history = $state<AlarmRuleVersion[] | null>(null);
	let historyError = $state<unknown>(null);

	// Editor text when nothing stored yet: every rule commented out.
	const example = `# Alarm rules, evaluated every minute. To use a rule below, uncomment it and
# change "alarms: []" to "alarms:". Names must be unique; severity is critical,
# major, minor or warning. Devices take fixed conditions as in job targets
# (default: all active devices).
alarms: []
#  # A device that has not contacted the server for an hour.
#  - name: offline-1h
#    severity: major
#    devices: { product_class: Box }
#    when: { offline_minutes: 60 }
#  # The latest value of a time series crosses a threshold (above and/or below).
#  - name: wifi-noise
#    severity: minor
#    when: { metric: Device.WiFi.Radio.1.Stats.Noise, above: -70 }
#  # At least 5 boot Informs within an hour.
#  - name: boot-storm
#    severity: warning
#    when: { event: inform, detail: { events: ["1 BOOT"] }, count: 5, within_minutes: 60 }
#  # A WireGuard device member without a handshake for 10 minutes (at least 3).
#  - name: wg-handshake
#    severity: major
#    when: { wg_handshake_minutes: 10 }
# More than this many alarms of one rule raised (or cleared) in one evaluation are
# notified as a single alarm.storm webhook (default 50, 0: never group).
# storm_threshold: 50
`;

	async function load() {
		try {
			if (admin) {
				settings = await api.alarmRuleSettings();
				rules = settings.rules.alarms;
			} else {
				rules = await api.alarmRules();
			}
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		void admin;
		load();
	});

	function startEdit() {
		draft = settings?.yaml ?? example;
		saveError = '';
		editing = true;
	}

	async function save() {
		saving = true;
		saveError = '';
		try {
			settings = await api.setAlarmRules(draft);
			rules = settings.rules.alarms;
			editing = false;
		} catch (e) {
			saveError = e instanceof Error ? e.message : String(e);
		} finally {
			saving = false;
		}
	}

	async function openHistory() {
		historyOpen = true;
		history = null;
		historyError = null;
		try {
			history = await api.alarmRuleHistory();
		} catch (e) {
			historyError = e;
		}
	}

	function restore(v: AlarmRuleVersion) {
		draft = v.yaml ?? '';
		saveError = '';
		editing = true;
		historyOpen = false;
	}

	function condition(r: AlarmRule): string {
		const w = r.when;
		if (w.offline_minutes !== undefined) return m.alarmRules.offline(w.offline_minutes);
		if (w.wg_handshake_minutes !== undefined)
			return m.alarmRules.wgHandshake(w.wg_handshake_minutes);
		if (w.metric !== undefined) {
			const parts = [
				w.above != null && m.alarmRules.above(w.above),
				w.below != null && m.alarmRules.below(w.below)
			].filter(Boolean);
			return `${w.metric} ${parts.join(` ${m.alarmRules.or} `)}`;
		}
		if (w.event !== undefined) {
			const text = m.alarmRules.event(w.count ?? 0, w.event, w.within_minutes ?? 0);
			return w.detail != null ? `${text}, ${JSON.stringify(w.detail)}` : text;
		}
		return JSON.stringify(w);
	}

	function devices(r: AlarmRule): string {
		const f = r.devices ?? {};
		const parts = [
			f.protocol,
			f.oui && `OUI ${f.oui}`,
			f.product_class,
			f.status,
			...(f.software_version ?? []),
			...(f.tags ?? []).map((t) => `#${t}`),
			...Object.entries(f.attributes ?? {}).map(([k, v]) => `${k}=${v}`),
			...(f.device_ids ?? []).map((d) => d.slice(0, 8))
		].filter(Boolean);
		return parts.length ? parts.join(', ') : m.alarmRules.allDevices;
	}

	const severityColor: Record<string, string> = {
		critical: 'bg-red-600 text-white',
		major: 'bg-red-100 text-red-800',
		minor: 'bg-amber-100 text-amber-800',
		warning: 'bg-sky-100 text-sky-800'
	};
</script>

<section class="mt-8">
	<div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between md:gap-4">
		<div class="min-w-0">
			<h2 class="text-lg font-semibold">{m.alarmRules.title}</h2>
			<p class="text-sm text-slate-600">{m.alarmRules.intro}</p>
			{#if settings?.source === 'file'}
				<p class="mt-1 text-sm text-slate-600">
					{m.alarmRules.fromFile}{#if settings.path}: <code
							class="font-mono break-all md:break-normal">{settings.path}</code
						>{/if}
				</p>
			{:else if settings?.updated_at}
				<p class="mt-1 text-xs text-slate-500" title={settings.updated_at}>
					{m.alarmRules.updated(settings.updated_by, ago(settings.updated_at))}
				</p>
			{/if}
		</div>
		{#if admin && settings?.editable}
			<div class="flex gap-2">
				<button
					onclick={openHistory}
					class="rounded border border-slate-300 px-3 py-2.5 text-sm hover:bg-slate-100 md:py-1.5"
					>{m.alarmRules.history}</button
				>
				{#if !editing}
					<button
						onclick={startEdit}
						class="rounded bg-teal-700 px-3 py-2.5 text-sm text-white hover:bg-teal-800 md:py-1.5"
						>{m.alarmRules.edit}</button
					>
				{/if}
			</div>
		{/if}
	</div>

	{#if editing}
		<div class="mt-3 rounded-md border border-slate-200 bg-white p-4 text-sm">
			<label class="block"
				><span class="text-slate-600">{m.alarmRules.yamlLabel}</span>
				<textarea
					bind:value={draft}
					rows="20"
					spellcheck="false"
					class="mt-1 w-full rounded border-slate-300 font-mono text-xs"
				></textarea></label
			>
			{#if saveError}
				<p class="mt-2 text-sm whitespace-pre-wrap text-red-700">{saveError}</p>
			{/if}
			<p class="mt-2 text-sm text-amber-800">{m.alarmRules.removesClear}</p>
			<div class="mt-2 flex gap-2">
				<button
					onclick={save}
					disabled={saving}
					class="rounded bg-teal-700 px-3 py-2.5 text-sm text-white hover:bg-teal-800 disabled:opacity-50 md:py-1.5"
					>{m.alarmRules.save}</button
				>
				<button
					onclick={() => (editing = false)}
					disabled={saving}
					class="rounded border border-slate-300 px-3 py-2.5 text-sm hover:bg-slate-100 md:py-1.5"
					>{m.common.cancel}</button
				>
			</div>
		</div>
	{/if}

	{#if error}
		<div class="mt-3"><ErrorBox {error} onretry={load} /></div>
	{:else if !rules}
		<p class="mt-3 text-slate-500">{m.common.loading}</p>
	{:else if rules.length === 0}
		<p class="mt-3 text-slate-500">{m.alarmRules.empty}</p>
	{:else}
		<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600">
					<tr>
						<th class="px-3 py-2">{m.alarmRules.name}</th>
						<th class="px-3 py-2">{m.alarmRules.severity}</th>
						<th class="px-3 py-2">{m.alarmRules.condition}</th>
						<th class="px-3 py-2">{m.alarmRules.devices}</th>
					</tr>
				</thead>
				<tbody>
					{#each rules as r (r.name)}
						<tr class="border-t border-slate-100">
							<td class="px-3 py-2 font-mono font-medium md:font-normal">{r.name}</td>
							<td class="px-3 py-2" data-label={m.alarmRules.severity}
								><span class="rounded px-2 py-0.5 text-xs {severityColor[r.severity] ?? ''}"
									>{r.severity}</span
								></td
							>
							<td class="px-3 py-2" data-label={m.alarmRules.condition}>{condition(r)}</td>
							<td class="px-3 py-2 text-slate-600" data-label={m.alarmRules.devices}
								>{devices(r)}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</section>

{#if historyOpen}
	<Modal title={m.alarmRules.historyTitle} onclose={() => (historyOpen = false)}>
		{#if historyError}
			<ErrorBox error={historyError} onretry={openHistory} />
		{:else if !history}
			<p class="text-slate-500">{m.common.loading}</p>
		{:else if history.length === 0}
			<p class="text-slate-500">{m.alarmRules.historyEmpty}</p>
		{:else}
			<ul class="divide-y divide-slate-100">
				{#each history as v, i (i)}
					<li class="flex items-center justify-between gap-4 py-2">
						<div>
							<div>{v.actor ?? m.common.none}</div>
							<div class="text-xs text-slate-500" title={v.at}>
								{new Date(v.at).toLocaleString()} ({ago(v.at)})
							</div>
						</div>
						{#if v.yaml !== null}
							<button
								onclick={() => restore(v)}
								class="rounded border border-slate-300 px-2 py-1 text-xs hover:bg-slate-100"
								>{m.alarmRules.restore}</button
							>
						{:else}
							<span class="text-xs text-slate-500">{m.alarmRules.removed}</span>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</Modal>
{/if}
