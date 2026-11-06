<script lang="ts">
	import { page } from '$app/state';
	import {
		ago,
		api,
		download,
		type DryRunItem,
		type Preset,
		type ScriptTrace as Trace,
		type StoredPreset
	} from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import ScriptTrace from '$lib/components/ScriptTrace.svelte';
	import { m } from '$lib/messages';

	let presets = $state<StoredPreset[] | null>(null);
	let source = $state<'database' | 'file'>('database');
	let error = $state<unknown>(null);
	let importing = $state(false);
	let yaml = $state('');
	let importNote = $state('');

	const EVENTS = [
		'0 BOOTSTRAP',
		'1 BOOT',
		'2 PERIODIC',
		'4 VALUE CHANGE',
		'6 CONNECTION REQUEST',
		'USP CONNECT'
	];
	let deviceId = $state(page.url.searchParams.get('device') ?? '');
	let events = $state<string[]>(['1 BOOT']);
	let newDevice = $state(false);
	let busy = $state(false);
	let result = $state<{ items: DryRunItem[]; scripts: Trace[] } | null>(null);
	let dryError = $state<unknown>(null);

	async function load() {
		try {
			const r = await api.presets();
			presets = r.items;
			source = r.source;
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});

	function when(p: Preset): string {
		const w = p.when;
		const parts = [
			...(w.events ?? []),
			w.oui && `OUI ${w.oui}`,
			w.product_class,
			w.software_version && `version ~ ${w.software_version}`,
			...(w.tags ?? []).map((t) => `#${t}`),
			w.new_device === true ? 'new device' : w.new_device === false ? 'known device' : null,
			...Object.entries(w.attributes ?? {}).map(([k, v]) => `${k}=${v}`)
		].filter(Boolean);
		return parts.length ? parts.join(', ') : m.presets.always;
	}

	async function runImport(dryRun: boolean) {
		importNote = '';
		try {
			const r = await api.importPresets(yaml, dryRun);
			importNote = m.presets.importResult(r.created.length, r.updated.length, r.unchanged.length);
			if (!dryRun) {
				yaml = '';
				await load();
			}
		} catch (e) {
			importNote = e instanceof Error ? e.message : String(e);
		}
	}

	async function dryRun(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			result = await api.presetDryRun(deviceId.trim(), events, newDevice);
			dryError = null;
		} catch (err) {
			dryError = err;
			result = null;
		} finally {
			busy = false;
		}
	}
</script>

<div class="flex flex-wrap items-center gap-3">
	<h1 class="text-xl font-semibold">{m.presets.title}</h1>
	<div class="flex flex-wrap gap-2 text-sm md:ml-auto">
		{#if source === 'database'}
			<a
				href="/presets/edit"
				class="rounded bg-teal-700 px-3 py-2.5 text-white hover:bg-teal-800 md:py-1.5"
				>{m.presets.create}</a
			>
			<button
				onclick={() => (importing = !importing)}
				class="rounded border border-slate-300 px-3 py-2.5 hover:bg-slate-100 md:py-1.5"
				>{m.presets.importYaml}</button
			>
		{/if}
		<button
			onclick={() => download('/presets/export.yaml', 'presets.yaml').catch((e) => (error = e))}
			class="rounded border border-slate-300 px-3 py-2.5 hover:bg-slate-100 md:py-1.5"
			>{m.presets.exportYaml}</button
		>
	</div>
</div>
<p class="mt-2 text-sm text-slate-600 md:mt-0">{m.presets.intro}</p>
{#if source === 'file'}
	<p class="mt-2 rounded bg-amber-50 px-3 py-2 text-sm text-amber-900">{m.presets.fromFile}</p>
{/if}
{#if importing}
	<div class="mt-3 rounded-md border border-slate-200 bg-white p-4 text-sm">
		<p class="text-slate-600">{m.presets.importHint}</p>
		<textarea
			bind:value={yaml}
			rows="10"
			spellcheck="false"
			class="mt-2 block w-full rounded border-slate-300 font-mono text-xs"
		></textarea>
		<div class="mt-2 flex flex-wrap items-center gap-2">
			<button
				onclick={() => runImport(true)}
				class="rounded border border-slate-300 px-3 py-2.5 hover:bg-slate-100 md:py-1.5"
				>{m.presets.importCheck}</button
			>
			<button
				onclick={() => runImport(false)}
				class="rounded bg-teal-700 px-3 py-2.5 text-white hover:bg-teal-800 md:py-1.5"
				>{m.presets.importApply}</button
			>
			{#if importNote}<span class="text-slate-700">{importNote}</span>{/if}
		</div>
	</div>
{/if}

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !presets}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else if presets.length === 0}
	<p class="mt-4 text-slate-500">{m.presets.empty}</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					<th class="px-3 py-2">{m.presets.name}</th>
					<th class="px-3 py-2">{m.presets.when}</th>
					<th class="px-3 py-2">{m.presets.does}</th>
				</tr>
			</thead>
			<tbody>
				{#each presets as sp (sp.name)}
					{@const p = sp.definition}
					<tr class="border-t border-slate-100 align-top {sp.enabled ? '' : 'text-slate-400'}">
						<td class="px-3 py-2 font-medium">
							<div class="min-w-0">
								{#if source === 'database'}<a
										href="/presets/edit?name={encodeURIComponent(sp.name)}"
										class="text-teal-800 hover:underline">{sp.name}</a
									>{:else}{sp.name}{/if}
								{#if !sp.enabled}<span class="ml-1 text-xs font-normal">{m.presets.disabled}</span
									>{/if}
								{#if p.once}<div class="text-xs font-normal text-slate-500">
										{m.presets.once}
									</div>{/if}
								{#if sp.revision !== null}<div class="text-xs font-normal text-slate-500">
										{m.presets.updated(sp.updated_by ?? '?', ago(sp.updated_at))}
									</div>{/if}
							</div>
						</td>
						<td class="px-3 py-2 text-slate-600" data-label={m.presets.when}>{when(p)}</td>
						<td class="px-3 py-2" data-label={m.presets.does}>
							<div class="min-w-0">
								{#each p.run ?? [] as t, i (i)}
									<span class="mr-1 rounded bg-teal-50 px-1.5 py-0.5 text-xs text-teal-800"
										>{t.kind}</span
									>
								{/each}
								{#if p.script || p.script_source}
									<span class="rounded bg-violet-50 px-1.5 py-0.5 text-xs text-violet-800"
										>{m.presets.script(p.script ?? `${p.name}.rn`)}</span
									>
									{#if p.args && Object.keys(p.args).length}
										<div class="mt-1 font-mono text-xs text-slate-500">
											{Object.entries(p.args)
												.map(([k, v]) => `${k}=${v}`)
												.join(' ')}
										</div>
									{/if}
								{/if}
							</div>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<h2 class="mt-8 text-lg font-semibold">{m.presets.dryRun}</h2>
	<p class="text-sm text-slate-600">{m.presets.dryRunIntro}</p>
	<form
		onsubmit={dryRun}
		class="mt-3 flex flex-wrap items-end gap-4 rounded-md border border-slate-200 bg-white p-4 text-sm"
	>
		<label class="block w-full md:w-auto">
			<span class="text-slate-600">{m.presets.device}</span>
			<input
				bind:value={deviceId}
				required
				class="mt-1 block w-full rounded border-slate-300 font-mono text-sm md:w-80"
			/>
		</label>
		<fieldset>
			<legend class="text-slate-600">{m.presets.events}</legend>
			<div class="mt-1 flex flex-wrap gap-3">
				{#each EVENTS as ev (ev)}
					<label class="flex items-center gap-1"
						><input type="checkbox" value={ev} bind:group={events} />{ev}</label
					>
				{/each}
			</div>
		</fieldset>
		<label class="flex items-center gap-1"
			><input type="checkbox" bind:checked={newDevice} />{m.presets.newDevice}</label
		>
		<button
			disabled={busy}
			class="rounded bg-teal-700 px-4 py-2.5 text-white hover:bg-teal-800 disabled:opacity-50 md:px-3 md:py-1.5"
			>{m.presets.run}</button
		>
	</form>

	{#if dryError}
		<div class="mt-3"><ErrorBox error={dryError} onretry={() => (dryError = null)} /></div>
	{:else if result}
		{#if result.items.length === 0 && result.scripts.length === 0}
			<p class="mt-3 text-sm text-slate-500">{m.presets.noMatch}</p>
		{/if}
		{#if result.items.length}
			<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="stack min-w-full text-sm">
					<tbody>
						{#each result.items as it, i (i)}
							<tr class="border-t border-slate-100 align-top first:border-t-0">
								<td class="px-3 py-2 font-medium">
									<div class="min-w-0">
										{it.preset}
										{#if it.script}<span
												class="ml-1 rounded bg-violet-50 px-1.5 py-0.5 text-xs text-violet-800"
												>{m.presets.fromScript}</span
											>{/if}
									</div>
								</td>
								<td class="px-3 py-2">{it.kind}</td>
								<td class="px-3 py-2 font-mono text-xs">{JSON.stringify(it.payload)}</td>
								<td class="px-3 py-2 text-xs text-slate-500"
									>{it.would_queue ? m.presets.wouldQueue : m.presets.alreadyRan}</td
								>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
		{#if result.scripts.length}
			<h3 class="mt-4 text-sm font-medium text-slate-700">{m.presets.traces}</h3>
			<ul class="mt-2 space-y-2">
				{#each result.scripts as t, i (i)}
					<li class="rounded-md border border-slate-200 bg-white p-3"><ScriptTrace trace={t} /></li>
				{/each}
			</ul>
		{/if}
	{/if}
{/if}
