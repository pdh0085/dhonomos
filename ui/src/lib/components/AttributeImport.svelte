<script lang="ts">
	import { api, type AttributeImport } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';

	let { ondone }: { ondone: () => void } = $props();

	let input = $state<HTMLInputElement | null>(null);
	let file = $state<File | null>(null);
	let preview = $state<AttributeImport | null>(null);
	let done = $state<number | null>(null);
	let busy = $state(false);
	let error = $state<unknown>(null);

	async function chosen() {
		file = input?.files?.[0] ?? null;
		preview = null;
		done = null;
		error = null;
		if (!file) return;
		busy = true;
		try {
			preview = await api.importAttributes(file, true);
		} catch (e) {
			error = e;
		} finally {
			busy = false;
		}
	}

	async function apply() {
		if (!file) return;
		busy = true;
		try {
			done = (await api.importAttributes(file, false)).updated;
			preview = null;
			ondone();
		} catch (e) {
			error = e;
		} finally {
			busy = false;
			if (input) input.value = '';
		}
	}
</script>

<span class="relative">
	<button
		onclick={() => input?.click()}
		title={m.devices.importHint}
		class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
		>{m.devices.importAttributes}</button
	>
	<input bind:this={input} type="file" accept=".csv,text/csv" class="hidden" onchange={chosen} />
</span>

{#if error || preview || done !== null}
	<div class="basis-full rounded-md border border-slate-200 bg-white p-3 text-sm">
		{#if error}
			<ErrorBox {error} onretry={() => (error = null)} />
		{:else if done !== null}
			<p>{m.devices.importDone(done)}</p>
		{:else if preview}
			<p class="font-medium">{m.devices.importSummary(preview.rows, preview.matched)}</p>
			<ul class="mt-1 list-disc pl-5 text-slate-600">
				{#if preview.unknown_count}<li>
						{m.devices.importUnknown(preview.unknown_count)}:
						<span class="font-mono text-xs break-all"
							>{preview.unknown.slice(0, 10).join(', ')}</span
						>
					</li>{/if}
				{#if preview.ambiguous.length}<li>
						{m.devices.importAmbiguous(preview.ambiguous.length)}:
						<span class="font-mono text-xs break-all"
							>{preview.ambiguous.slice(0, 10).join(', ')}</span
						>
					</li>{/if}
				{#if preview.invalid_count}<li>
						{m.devices.importInvalid(preview.invalid_count)}:
						{#each preview.invalid.slice(0, 5) as r (r.line)}<span class="text-xs"
								>line {r.line} ({r.error});
							</span>{/each}
					</li>{/if}
			</ul>
			<div class="mt-2 flex flex-wrap gap-2">
				<button
					disabled={busy || preview.matched === 0}
					onclick={apply}
					class="rounded bg-teal-700 px-3 py-1.5 text-white hover:bg-teal-800 disabled:opacity-50"
					>{m.devices.importApply(preview.matched)}</button
				>
				<button
					onclick={() => (preview = null)}
					class="rounded border border-slate-300 px-3 py-1.5 hover:bg-slate-50"
					>{m.common.cancel}</button
				>
			</div>
		{/if}
	</div>
{/if}
