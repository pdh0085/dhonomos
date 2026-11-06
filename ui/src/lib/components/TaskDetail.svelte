<script lang="ts">
	import type { Task } from '$lib/api';
	import { m } from '$lib/messages';

	let { task }: { task: Task } = $props();

	// Task origin: preset, bulk job or operator.
	const origin = $derived.by(() => {
		const by = task.created_by ?? '';
		if (task.job_id) return { text: by || 'job', href: `/jobs/${task.job_id}` };
		if (by.startsWith('preset:'))
			return { text: by, href: `/presets/edit?name=${encodeURIComponent(by.slice(7))}` };
		return { text: by || '—', href: null };
	});

	const dot: Record<string, string> = {
		succeeded: 'bg-teal-600',
		failed: 'bg-red-600',
		retry: 'bg-amber-500',
		waiting: 'bg-sky-500',
		cancelled: 'bg-slate-400',
		expired: 'bg-slate-400'
	};

	const time = (iso: string) => new Date(iso).toLocaleString();
	const pretty = (v: unknown) => JSON.stringify(v, null, 2);
</script>

<div class="grid gap-4 md:grid-cols-2">
	<div>
		<h4 class="text-xs font-medium text-slate-500 uppercase">{m.tasks.trace}</h4>
		{#if task.trace?.length}
			<ol class="mt-2 space-y-2 border-l border-slate-200 pl-4">
				{#each task.trace as s, i (i)}
					<li class="relative">
						<span
							class="absolute top-1.5 -left-[21px] h-2.5 w-2.5 rounded-full {dot[s.step] ??
								'bg-slate-300'}"
						></span>
						<div class="text-sm">
							{m.tasks.steps[s.step] ?? s.step}
							{#if s.attempt > 0}<span class="text-xs text-slate-500"
									>· {m.tasks.attempt(s.attempt)}</span
								>{/if}
						</div>
						<div class="text-xs text-slate-500">{time(s.at)}</div>
						{#if s.detail && s.step !== 'queued'}<div
								class="font-mono text-xs break-all text-red-800"
							>
								{s.detail}
							</div>{/if}
					</li>
				{/each}
			</ol>
		{:else}
			<p class="mt-2 text-sm text-slate-500">{m.tasks.noTrace}</p>
		{/if}
		<h4 class="mt-4 text-xs font-medium text-slate-500 uppercase">{m.tasks.origin}</h4>
		<p class="mt-1 text-sm">
			{#if origin.href}<a href={origin.href} class="text-teal-800 hover:underline">{origin.text}</a
				>{:else}{origin.text}{/if}
		</p>
	</div>
	<div>
		<h4 class="text-xs font-medium text-slate-500 uppercase">{m.tasks.payload}</h4>
		<pre class="mt-1 overflow-x-auto rounded bg-slate-50 p-2 text-xs">{pretty(task.payload)}</pre>
		{#if task.result}
			<h4 class="mt-3 text-xs font-medium text-slate-500 uppercase">{m.tasks.resultFull}</h4>
			<pre class="mt-1 max-h-80 overflow-auto rounded bg-slate-50 p-2 text-xs">{pretty(
					task.result
				)}</pre>
		{/if}
	</div>
</div>
