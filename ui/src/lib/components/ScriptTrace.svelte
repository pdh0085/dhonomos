<script lang="ts">
	import type { ScriptTrace } from '$lib/api';
	import { m } from '$lib/messages';

	let { trace }: { trace: ScriptTrace } = $props();

	const changed = $derived(
		trace.tasks.length +
			trace.tags_added.length +
			trace.tags_removed.length +
			(trace.virtual?.length ?? 0) >
			0
	);
</script>

<div class="text-xs">
	<div class="flex flex-wrap items-center gap-2">
		<span class="font-medium">{trace.preset}</span>
		<span class="font-mono text-slate-500">{trace.script}</span>
		<span class="text-slate-500">{trace.duration_ms} ms</span>
		{#if trace.error}
			<span class="rounded bg-red-100 px-1.5 py-0.5 text-red-800">{m.presets.failed}</span>
		{/if}
		{#each trace.tasks as t, i (i)}
			<span class="rounded bg-teal-50 px-1.5 py-0.5 text-teal-800">{t}</span>
		{/each}
		{#each trace.tags_added as t (t)}
			<span class="rounded bg-slate-100 px-1.5 py-0.5">+#{t}</span>
		{/each}
		{#each trace.tags_removed as t (t)}
			<span class="rounded bg-slate-100 px-1.5 py-0.5 line-through">#{t}</span>
		{/each}
	</div>
	{#if trace.error}
		<pre class="mt-1 whitespace-pre-wrap text-red-800">{trace.error}</pre>
	{:else if !changed}
		<p class="mt-1 text-slate-500">{m.presets.nothing}</p>
	{/if}
	<dl class="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
		{#if trace.declared.length}
			<dt class="text-slate-500">{m.presets.declared}</dt>
			<dd class="font-mono">
				{#each trace.declared as [p, v], i (i)}<div>{p} = {v}</div>{/each}
			</dd>
		{/if}
		{#if trace.virtual?.length}
			<dt class="text-slate-500">{m.presets.virtual}</dt>
			<dd class="font-mono">
				{#each trace.virtual as [p, v], i (i)}<div>{p} = {v ?? ''}</div>{/each}
			</dd>
		{/if}
		{#if trace.reads.length}
			<dt class="text-slate-500">{m.presets.reads}</dt>
			<dd class="font-mono text-slate-600">
				{#each trace.reads as [p, v], i (i)}<div>{p} → {v ?? '∅'}</div>{/each}
			</dd>
		{/if}
		{#if trace.logs.length}
			<dt class="text-slate-500">{m.presets.logs}</dt>
			<dd>
				{#each trace.logs as l, i (i)}<div>{l}</div>{/each}
			</dd>
		{/if}
	</dl>
</div>
