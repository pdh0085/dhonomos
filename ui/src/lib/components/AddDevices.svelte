<script lang="ts">
	import { api, type BulkReport, type BulkResult } from '$lib/api';
	import { MAX_BULK, entryLabel, parseDeviceList, type ListLine } from '$lib/devicelist';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';

	let { onclose, ondone }: { onclose: () => void; ondone: () => void } = $props();

	const MAX_FILE_MB = 2;
	const SHOWN = 300;

	let text = $state('');
	let tagsText = $state('');
	let busy = $state(false);
	let error = $state<unknown>(null);
	// Server answer for the lines: preview (dry run), then the real run.
	let report = $state<BulkReport | null>(null);
	let sent = $state<ListLine[]>([]);

	const lines = $derived(parseDeviceList(text));
	const usable = $derived(lines.filter((l) => l.entry));
	const tags = $derived(
		tagsText
			.split(',')
			.map((t) => t.trim())
			.filter((t) => t)
	);
	const tooMany = $derived(usable.length > MAX_BULK);

	// Line + server answer for it.
	interface Row {
		line: ListLine;
		result?: BulkResult;
	}
	const rows = $derived.by((): Row[] => {
		if (!report) return [];
		const byIndex = new Map(report.results.map((r) => [r.index, r]));
		const rows: Row[] = lines
			.filter((l) => !l.entry)
			.map((line) => ({ line }))
			.concat(sent.map((line, i) => ({ line, result: byIndex.get(i) })));
		return rows.sort((a, b) => a.line.line - b.line.line);
	});
	const localInvalid = $derived(lines.filter((l) => !l.entry).length);
	const invalidTotal = $derived((report?.invalid ?? 0) + localInvalid);

	function edited() {
		report = null;
		error = null;
	}

	async function load(e: Event & { currentTarget: HTMLInputElement }) {
		const file = e.currentTarget.files?.[0];
		e.currentTarget.value = '';
		if (!file) return;
		if (file.size > MAX_FILE_MB << 20) {
			error = new Error(m.devices.add.fileTooBig(MAX_FILE_MB));
			return;
		}
		text = await file.text();
		edited();
	}

	async function send(dryRun: boolean) {
		if (busy || tooMany) return;
		busy = true;
		error = null;
		try {
			sent = usable;
			if (usable.length === 0) {
				// Only unreadable lines -> nothing to ask the server.
				report = { dry_run: true, total: 0, added: 0, exists: 0, invalid: 0, results: [] };
				return;
			}
			report = await api.preregisterDevices(
				usable.map((l) => l.entry!),
				tags,
				dryRun
			);
			if (!dryRun) ondone();
		} catch (e) {
			error = e;
		} finally {
			busy = false;
		}
	}

	const label = (r: Row) =>
		r.result?.endpoint_id ?? (r.line.entry ? entryLabel(r.line.entry) : r.line.text);
</script>

<Modal title={m.devices.add.title} {onclose}>
	<div class="space-y-3">
		<p>{m.devices.add.intro}</p>
		<details class="rounded border border-slate-200 bg-slate-50 px-3 py-2">
			<summary class="cursor-pointer font-medium">{m.devices.add.formatsTitle}</summary>
			<ul class="mt-2 list-disc space-y-1 pl-5 text-slate-700">
				{#each m.devices.add.formats as f (f)}<li>{f}</li>{/each}
			</ul>
			<p class="mt-2 text-slate-700">{m.devices.add.formatsCsv}</p>
		</details>

		<label class="block"
			><span>{m.devices.add.list}</span><textarea
				bind:value={text}
				oninput={edited}
				rows="8"
				spellcheck="false"
				class="mt-1 block w-full rounded border-slate-300 font-mono text-sm"
				placeholder="os::B01408-B01408123456&#10;B01408,B01408123456"
			></textarea></label
		>
		<div class="flex flex-wrap items-end gap-4">
			<label class="block max-w-full"
				><span>{m.devices.add.file}</span><input
					type="file"
					accept=".csv,.txt,text/csv,text/plain"
					onchange={load}
					class="mt-1 block max-w-full text-sm"
				/></label
			>
			<label class="block min-w-48 flex-1"
				><span>{m.devices.add.tags}</span><input
					bind:value={tagsText}
					oninput={edited}
					class="mt-1 block w-full rounded border-slate-300 text-sm"
				/></label
			>
		</div>
		{#if tooMany}<p class="text-red-700">{m.devices.add.tooMany(MAX_BULK)}</p>{/if}
		{#if error}<ErrorBox {error} onretry={() => (error = null)} />{/if}

		{#if report}
			<div class="space-y-2 rounded border border-slate-200 p-3">
				<p class="font-medium">
					{#if report.dry_run}
						{m.devices.add.summary(report.added, report.exists, invalidTotal)}
					{:else}
						{m.devices.add.done(report.added, report.exists, invalidTotal)}
					{/if}
				</p>
				<div class="max-h-72 overflow-y-auto">
					<table class="min-w-full text-left text-xs">
						<thead class="text-slate-500">
							<tr
								><th class="py-1 pr-3">{m.devices.add.line}</th><th class="py-1 pr-3"
									>{m.devices.add.device}</th
								><th class="py-1">{m.devices.add.result}</th></tr
							>
						</thead>
						<tbody>
							{#each rows.slice(0, SHOWN) as r (r.line.line)}
								<tr class="border-t border-slate-100">
									<td class="py-1 pr-3 text-slate-500">{r.line.line}</td>
									<td class="py-1 pr-3 font-mono break-all">
										{label(r)}
										{#if r.result?.protocol}<span
												class="ml-1 rounded bg-slate-100 px-1 py-0.5 text-slate-700 uppercase whitespace-nowrap"
												>{r.result.protocol}</span
											>{/if}
									</td>
									<td class="py-1">
										{#if !r.result}
											<span class="text-red-700">{m.devices.add.invalid}: {r.line.error}</span>
										{:else if r.result.status === 'invalid'}
											<span class="text-red-700">{m.devices.add.invalid}: {r.result.error}</span>
										{:else if r.result.status === 'exists'}
											<a class="text-teal-800 hover:underline" href="/devices/{r.result.device_id}"
												>{m.devices.add.exists}</a
											>
										{:else}
											<span class="text-teal-800"
												>{report.dry_run ? m.devices.add.willAdd : m.devices.add.added}</span
											>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
					{#if rows.length > SHOWN}<p class="pt-2 text-slate-500">
							{m.devices.add.more(rows.length - SHOWN)}
						</p>{/if}
				</div>
			</div>
		{/if}

		<div class="flex flex-wrap gap-2">
			{#if report?.dry_run && report.added > 0}
				<button
					type="button"
					disabled={busy}
					onclick={() => send(false)}
					class="rounded bg-teal-700 px-4 py-2 text-white hover:bg-teal-800 disabled:opacity-50"
					>{busy ? m.devices.add.adding : m.devices.add.submit(report.added)}</button
				>
			{/if}
			{#if !report || report.dry_run}
				<button
					type="button"
					disabled={busy || lines.length === 0 || tooMany}
					onclick={() => send(true)}
					class="rounded border border-slate-300 bg-white px-4 py-2 hover:bg-slate-50 disabled:opacity-50"
					>{busy && (!report || report.dry_run)
						? m.devices.add.previewing
						: m.devices.add.preview}</button
				>
			{/if}
			<button
				type="button"
				onclick={onclose}
				class="rounded border border-slate-300 bg-white px-4 py-2 hover:bg-slate-50"
				>{report && !report.dry_run ? m.common.close : m.common.cancel}</button
			>
		</div>
	</div>
</Modal>
