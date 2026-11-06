<script lang="ts">
	import { untrack } from 'svelte';
	import { api, ApiError, type BundleRequest, type BundleResult } from '$lib/api';
	import { MAX_BUNDLE, parseDeviceList } from '$lib/devicelist';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';

	let {
		ids,
		skipped,
		filter: initialFilter,
		ondone,
		oncancel
	}: {
		/** Selected devices that can get a certificate. */
		ids: string[];
		/** Selected devices that cannot: retired + CWMP devices without OUI + serial number. */
		skipped: { retired: number; unnamed: number };
		/** Filter expression of the list -> start value here. */
		filter: string;
		ondone: (result: BundleResult) => void;
		oncancel: () => void;
	} = $props();

	const MIN_PASSWORD = 12;
	const MAX_FILE_MB = 2;

	type Mode = 'selection' | 'list' | 'filter';
	// Start mode; props read once.
	let mode = $state<Mode>(untrack(() => ids.length) > 0 ? 'selection' : 'list');
	let days = $state(1095);
	let password = $state('');
	let repeat = $state('');
	let busy = $state(false);
	let error = $state<unknown>(null);

	// EndpointIDs or serial numbers.
	let text = $state('');
	let tagsText = $state('');
	const lines = $derived(parseDeviceList(text));
	const targets = $derived(
		lines
			.filter((l) => l.entry)
			.map((l) => {
				// Certificate is per EndpointID -> product class not needed.
				const { endpoint_id, oui, serial_number } = l.entry!;
				return { endpoint_id, oui, serial_number };
			})
	);
	const unreadable = $derived(lines.filter((l) => !l.entry).length);
	const tags = $derived(
		tagsText
			.split(',')
			.map((t) => t.trim())
			.filter((t) => t)
	);

	// Devices matched by the filter, counted before any issue.
	let expression = $state(untrack(() => initialFilter));
	let matches = $state<number | null>(null);
	let counting = $state(false);
	let countError = $state<unknown>(null);
	let counts = 0;
	let recount = $state(0);

	$effect(() => {
		void recount;
		const expr = expression.trim();
		if (mode !== 'filter' || !expr) {
			counts++;
			matches = null;
			countError = null;
			counting = false;
			return;
		}
		matches = null;
		countError = null;
		counting = true;
		const mine = ++counts;
		const t = setTimeout(async () => {
			try {
				// Server leaves retired devices out of the bundle -> not counted.
				const r = await api.devices({ filter: `(${expr}) and status != retired` }, 1, 0);
				if (mine === counts) matches = r.total;
			} catch (e) {
				if (mine === counts) countError = e;
			} finally {
				if (mine === counts) counting = false;
			}
		}, 400);
		return () => clearTimeout(t);
	});

	const count = $derived(
		mode === 'selection' ? ids.length : mode === 'list' ? targets.length : (matches ?? 0)
	);

	const skippedCount = $derived(skipped.retired + skipped.unnamed);

	// Server counts chars, not UTF-16 units.
	const problem = $derived.by(() => {
		if (mode === 'selection' && ids.length === 0)
			return skippedCount > 0 ? m.devices.bundle.noneEligible : m.devices.bundle.noneSelected;
		if (mode === 'list') {
			if (unreadable > 0) return m.devices.bundle.badLines(unreadable);
			if (targets.length === 0) return m.devices.bundle.listEmpty;
		}
		if (mode === 'filter') {
			if (!expression.trim()) return m.devices.bundle.filterEmpty;
			if (matches === 0) return m.devices.bundle.noMatches;
		}
		if (count > MAX_BUNDLE) return m.devices.bundle.tooMany(MAX_BUNDLE);
		if ([...password].length < MIN_PASSWORD) return m.devices.bundle.tooShort(MIN_PASSWORD);
		if (password !== repeat) return m.devices.bundle.mismatch;
		return '';
	});
	// Filter -> count first.
	const ready = $derived(!problem && (mode !== 'filter' || (matches !== null && !countError)));

	async function load(e: Event & { currentTarget: HTMLInputElement }) {
		const file = e.currentTarget.files?.[0];
		e.currentTarget.value = '';
		if (!file) return;
		if (file.size > MAX_FILE_MB << 20) {
			error = new Error(m.devices.add.fileTooBig(MAX_FILE_MB));
			return;
		}
		text = await file.text();
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!ready || busy) return;
		busy = true;
		error = null;
		const req: BundleRequest = { days, password };
		if (mode === 'selection') req.device_ids = ids;
		else if (mode === 'list') {
			req.targets = targets;
			req.create_missing = true;
			req.tags = tags;
		} else req.filter = expression.trim();
		try {
			const result = await api.issueCertificateBundle(req);
			password = '';
			repeat = '';
			ondone(result);
		} catch (err) {
			// Generic "not found" would hide the reason.
			error =
				err instanceof ApiError && err.status === 404 ? new ApiError(501, m.certs.disabled) : err;
		} finally {
			busy = false;
		}
	}
</script>

<Modal title={m.devices.bundle.title} onclose={oncancel}>
	<form onsubmit={submit} class="space-y-4">
		<p>{m.devices.bundle.intro}</p>
		<p class="rounded border border-amber-200 bg-amber-50 px-3 py-2 text-amber-900">
			{m.devices.bundle.warning}
		</p>

		<fieldset class="space-y-3">
			<legend class="font-medium">{m.devices.bundle.how}</legend>
			<label class="flex items-center gap-2">
				<input type="radio" bind:group={mode} value="selection" disabled={ids.length === 0} />
				{m.devices.bundle.modeSelection(ids.length)}
			</label>
			{#if mode === 'selection'}
				<p class="pl-6 text-slate-600">
					{ids.length > 0
						? m.devices.bundle.cwmpHint
						: skippedCount > 0
							? m.devices.bundle.noneEligible
							: m.devices.bundle.noneSelected}
				</p>
				{#if skippedCount > 0}
					<p class="rounded border border-amber-200 bg-amber-50 px-3 py-2 text-amber-900">
						{m.devices.bundle.skipped(skipped.retired, skipped.unnamed)}
					</p>
				{/if}
			{/if}
			<label class="flex items-center gap-2">
				<input type="radio" bind:group={mode} value="list" />
				{m.devices.bundle.modeList}
			</label>
			{#if mode === 'list'}
				<div class="space-y-2 pl-6">
					<p class="text-slate-600">{m.devices.bundle.listHint}</p>
					<label class="block"
						><span class="sr-only">{m.devices.bundle.list}</span><textarea
							bind:value={text}
							rows="6"
							spellcheck="false"
							aria-label={m.devices.bundle.list}
							class="block w-full rounded border-slate-300 font-mono text-sm"
							placeholder="os::B01408-B01408123456&#10;B01408,B01408123456"
						></textarea></label
					>
					<div class="flex flex-wrap items-end gap-4">
						<label class="block max-w-full"
							><span>{m.devices.bundle.file}</span><input
								type="file"
								accept=".csv,.txt,text/csv,text/plain"
								onchange={load}
								class="mt-1 block max-w-full text-sm"
							/></label
						>
						<label class="block min-w-48 flex-1"
							><span>{m.devices.bundle.tags}</span><input
								bind:value={tagsText}
								class="mt-1 block w-full rounded border-slate-300 text-sm"
							/></label
						>
					</div>
					{#if lines.length > 0}<p class="text-slate-600">
							{m.devices.count(targets.length)}{#if unreadable > 0}; {m.devices.bundle.badLines(
									unreadable
								)}
								<span class="font-mono text-xs break-all"
									>{lines
										.filter((l) => !l.entry)
										.slice(0, 3)
										.map((l) => `${l.line}: ${l.text}`)
										.join(' | ')}</span
								>{/if}
						</p>{/if}
				</div>
			{/if}
			<label class="flex items-center gap-2">
				<input type="radio" bind:group={mode} value="filter" />
				{m.devices.bundle.modeFilter}
			</label>
			{#if mode === 'filter'}
				<div class="space-y-2 pl-6">
					<p class="text-slate-600">{m.devices.bundle.filterHint}</p>
					<input
						bind:value={expression}
						aria-label={m.devices.bundle.filter}
						placeholder={m.devices.expression}
						spellcheck="false"
						class="block w-full rounded border-slate-300 font-mono text-sm"
					/>
					{#if counting}<p class="text-slate-600">{m.devices.bundle.counting}</p>
					{:else if countError}<ErrorBox error={countError} onretry={() => recount++} />
					{:else if matches !== null}<p class="font-medium">
							{m.devices.bundle.matches(matches)}
						</p>{/if}
				</div>
			{/if}
		</fieldset>

		<div class="flex flex-wrap gap-4">
			<label class="block"
				><span>{m.certs.days}</span><input
					type="number"
					min="1"
					max="3650"
					bind:value={days}
					class="mt-1 block w-32 rounded border-slate-300 text-sm"
				/></label
			>
			<label class="block w-full md:w-auto"
				><span>{m.devices.bundle.password(MIN_PASSWORD)}</span><input
					type="password"
					autocomplete="new-password"
					bind:value={password}
					class="mt-1 block w-full rounded border-slate-300 text-sm md:w-64"
				/></label
			>
			<label class="block w-full md:w-auto"
				><span>{m.devices.bundle.repeat}</span><input
					type="password"
					autocomplete="new-password"
					bind:value={repeat}
					class="mt-1 block w-full rounded border-slate-300 text-sm md:w-64"
				/></label
			>
		</div>
		{#if problem}<p class="text-xs text-slate-700">{problem}</p>{/if}
		{#if error}<ErrorBox {error} onretry={() => (error = null)} />{/if}
		<div class="flex flex-wrap gap-2">
			<button
				disabled={busy || !ready}
				class="rounded bg-teal-700 px-4 py-2 text-white hover:bg-teal-800 disabled:opacity-50"
				>{busy ? m.devices.bundle.working : m.devices.bundle.download}</button
			>
			<button
				type="button"
				onclick={oncancel}
				class="rounded border border-slate-300 bg-white px-4 py-2 hover:bg-slate-50"
				>{m.common.cancel}</button
			>
		</div>
	</form>
</Modal>
