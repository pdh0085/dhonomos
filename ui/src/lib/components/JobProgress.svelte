<script lang="ts">
	import type { JobCounts } from '$lib/api';
	import { m } from '$lib/messages';

	let { counts, total }: { counts: JobCounts; total: number } = $props();

	const segments = [
		['succeeded', 'bg-emerald-500'],
		['failed', 'bg-red-500'],
		['cancelled', 'bg-slate-400'],
		['verifying', 'bg-sky-300'],
		['dispatched', 'bg-sky-500']
	] as const;
	const done = $derived(counts.succeeded + counts.failed + counts.cancelled);
</script>

<div
	class="flex h-2.5 w-full overflow-hidden rounded bg-slate-200"
	title={m.jobs.ofTotal(done, total)}
>
	{#each segments as [key, color] (key)}
		{#if counts[key] > 0 && total > 0}
			<div class={color} style="width: {(counts[key] * 100) / total}%"></div>
		{/if}
	{/each}
</div>
