<script lang="ts">
	import { api, type Device } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';

	let { device, onsaved }: { device: Device; onsaved: (d: Device) => void } = $props();

	let editing = $state(false);
	let busy = $state(false);
	let error = $state<unknown>(null);
	let tags = $state('');
	let wsUrl = $state('');
	let rows = $state<{ key: string; value: string }[]>([]);

	const entries = $derived(
		Object.entries(device.attributes ?? {}).sort(([a], [b]) => a.localeCompare(b))
	);

	function start() {
		tags = device.tags.join(', ');
		wsUrl = device.usp_ws_url ?? '';
		rows = entries.map(([key, value]) => ({ key, value }));
		if (rows.length === 0) rows = [{ key: '', value: '' }];
		error = null;
		editing = true;
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const attributes: Record<string, string | null> = {};
			// Keys no longer present -> removed.
			for (const [k] of entries) attributes[k] = null;
			for (const r of rows) if (r.key.trim()) attributes[r.key.trim()] = r.value;
			const saved = await api.updateDevice(device.id, {
				tags: tags
					.split(',')
					.map((t) => t.trim())
					.filter(Boolean),
				attributes,
				...(device.protocol === 'usp' ? { usp_ws_url: wsUrl.trim() } : {})
			});
			editing = false;
			onsaved(saved);
		} catch (err) {
			error = err;
		} finally {
			busy = false;
		}
	}
</script>

<div class="mt-4 border-t border-slate-100 pt-3 text-sm">
	{#if !editing}
		<div class="flex flex-wrap items-start gap-x-8 gap-y-2">
			<div>
				<div class="text-slate-500">{m.labels.tags}</div>
				<div class="mt-0.5 flex flex-wrap gap-1">
					{#each device.tags as t (t)}
						<span class="rounded bg-slate-100 px-1.5 py-0.5 text-xs">#{t}</span>
					{:else}
						<span class="text-slate-400">{m.labels.none}</span>
					{/each}
				</div>
			</div>
			<div class="min-w-0 flex-1">
				<div class="text-slate-500" title={m.labels.attributesHint}>{m.labels.attributes}</div>
				<dl class="mt-0.5 flex flex-wrap gap-x-4 gap-y-0.5">
					{#each entries as [k, v] (k)}
						<div class="min-w-0 break-all md:break-normal">
							<dt class="inline text-slate-500">{k}</dt>
							<dd class="inline font-mono">{v}</dd>
						</div>
					{:else}
						<span class="text-slate-400">{m.labels.none}</span>
					{/each}
				</dl>
			</div>
			{#if device.protocol === 'usp' && device.usp_ws_url}
				<div class="min-w-0">
					<div class="text-slate-500" title={m.labels.wsUrlHint}>{m.labels.wsUrl}</div>
					<div class="mt-0.5 font-mono text-xs break-all md:break-normal">{device.usp_ws_url}</div>
				</div>
			{/if}
			<button onclick={start} class="py-2 text-xs text-teal-800 hover:underline md:py-0"
				>{m.labels.edit}</button
			>
		</div>
	{:else}
		<form onsubmit={save} class="space-y-3">
			<label class="block">
				<span class="text-slate-500">{m.labels.tags}</span>
				<input
					bind:value={tags}
					placeholder={m.labels.tagsHint}
					class="mt-1 block w-full max-w-xl rounded border-slate-300 text-sm"
				/>
			</label>
			{#if device.protocol === 'usp'}
				<label class="block">
					<span class="text-slate-500">{m.labels.wsUrl}</span>
					<input
						bind:value={wsUrl}
						placeholder="ws://agent.example:7650/usp"
						class="mt-1 block w-full max-w-xl rounded border-slate-300 font-mono text-sm"
					/>
					<span class="text-xs text-slate-500">{m.labels.wsUrlHint}</span>
				</label>
			{/if}
			<div>
				<div class="text-slate-500">{m.labels.attributes}</div>
				<p class="text-xs text-slate-500">{m.labels.attributesHint}</p>
				{#each rows as r, i (i)}
					<div class="mt-1 flex flex-wrap gap-2 md:flex-nowrap">
						<input
							bind:value={r.key}
							placeholder={m.labels.key}
							pattern="[A-Za-z0-9_.\-]{'{'}1,64{'}'}"
							class="w-full rounded border-slate-300 font-mono text-sm md:w-48"
						/>
						<input
							bind:value={r.value}
							placeholder={m.labels.value}
							maxlength="256"
							class="min-w-0 flex-1 rounded border-slate-300 font-mono text-sm md:w-72 md:flex-none"
						/>
						<button
							type="button"
							onclick={() => (rows = rows.filter((_, j) => j !== i))}
							class="text-xs text-slate-500 hover:text-red-700">{m.labels.remove}</button
						>
					</div>
				{/each}
				<button
					type="button"
					onclick={() => (rows = [...rows, { key: '', value: '' }])}
					class="mt-1 text-xs text-teal-800 hover:underline">{m.labels.add}</button
				>
			</div>
			{#if error}<ErrorBox {error} onretry={() => (error = null)} />{/if}
			<div class="flex flex-wrap gap-2">
				<button
					disabled={busy}
					class="rounded bg-teal-700 px-3 py-1.5 text-white hover:bg-teal-800 disabled:opacity-50"
					>{m.labels.save}</button
				>
				<button
					type="button"
					onclick={() => (editing = false)}
					class="rounded border border-slate-300 px-3 py-1.5 hover:bg-slate-50"
					>{m.common.cancel}</button
				>
			</div>
		</form>
	{/if}
</div>
