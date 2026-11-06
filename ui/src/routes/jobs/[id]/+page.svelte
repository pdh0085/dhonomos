<script lang="ts">
	import { page } from '$app/state';
	import { api, ago, download, type Job, type JobMember } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import JobProgress from '$lib/components/JobProgress.svelte';
	import { m } from '$lib/messages';
	import { stateColor } from '../state';

	const id = $derived(page.params.id ?? '');
	let job = $state<Job | null>(null);
	let failures = $state<JobMember[]>([]);
	let error = $state<unknown>(null);
	let notice = $state('');

	async function load() {
		try {
			const [j, f] = await Promise.all([api.job(id), api.jobMembers(id, 'failed')]);
			job = j;
			failures = f;
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
		const timer = setInterval(load, 3000);
		return () => clearInterval(timer);
	});

	async function act(action: string) {
		if (action === 'cancel' && !confirm(m.jobs.confirmCancel)) return;
		notice = '';
		try {
			job = await api.jobAction(id, action);
		} catch (e) {
			notice = e instanceof Error ? e.message : String(e);
		}
	}

	const actions = $derived.by(() => {
		if (!job) return [];
		const last = (job.stages?.length ?? 1) - 1;
		switch (job.state) {
			case 'draft':
				return ['start', 'cancel'];
			case 'running':
				return ['pause', 'cancel'];
			case 'paused':
				return [...(job.stage < last ? ['approve'] : []), 'resume', 'cancel'];
			default:
				return [];
		}
	});
	const countKeys = [
		'queued',
		'dispatched',
		'verifying',
		'succeeded',
		'failed',
		'cancelled'
	] as const;
</script>

<a href="/jobs" class="text-sm text-teal-800 hover:underline">← {m.jobs.back}</a>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !job}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else}
	<section class="mt-3 rounded-md border border-slate-200 bg-white p-4">
		<div class="flex flex-wrap items-start gap-4">
			<div class="min-w-0">
				<h1 class="text-xl font-semibold break-words">{job.name}</h1>
				<p class="text-sm text-slate-600">
					{m.tasks.kinds[job.task.kind] ?? job.task.kind} · {m.jobs.ofTotal(
						job.counts.succeeded + job.counts.failed + job.counts.cancelled,
						job.total
					)}
				</p>
			</div>
			<div class="ml-auto flex flex-wrap items-center gap-2">
				<span class="rounded px-2 py-0.5 text-xs {stateColor[job.state] ?? ''}">{job.state}</span>
				<button
					onclick={() =>
						download(`/jobs/${job?.id}/members.csv`, `job-${job?.id}.csv`).catch(
							(e) => (error = e)
						)}
					class="rounded border border-slate-300 px-3 py-2.5 text-sm hover:bg-slate-100 md:py-1.5"
					>{m.common.exportCsv}</button
				>
				{#each actions as a (a)}
					<button
						onclick={() => act(a)}
						class="rounded border px-3 py-2.5 text-sm md:py-1.5 {a === 'cancel'
							? 'border-red-300 text-red-700 hover:bg-red-50'
							: 'border-slate-300 hover:bg-slate-100'}">{m.jobs.actions[a]}</button
					>
				{/each}
			</div>
		</div>
		{#if job.reason}
			<p class="mt-3 rounded bg-amber-50 px-3 py-2 text-sm text-amber-900">{job.reason}</p>
		{/if}
		{#if notice}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm">{notice}</p>{/if}

		<div class="mt-4"><JobProgress counts={job.counts} total={job.total} /></div>
		<dl class="mt-4 grid grid-cols-3 gap-3 text-sm md:grid-cols-6">
			{#each countKeys as k (k)}
				<div>
					<dt class="text-slate-500">{m.jobs.counts[k]}</dt>
					<dd class="text-lg font-semibold tabular-nums">{job.counts[k]}</dd>
				</div>
			{/each}
		</dl>

		{#if job.stages}
			<div class="mt-4 flex flex-wrap items-center gap-2 text-sm">
				<span class="text-slate-500">{m.jobs.stage}</span>
				{#each job.stages as pct, i (i)}
					<span
						class="rounded-full px-3 py-1 text-xs {i < job.stage
							? 'bg-emerald-100 text-emerald-800'
							: i === job.stage
								? 'bg-teal-700 text-white'
								: 'bg-slate-100 text-slate-500'}">{pct}%</span
					>
				{/each}
			</div>
		{/if}
		<p class="mt-3 text-xs text-slate-500">
			{m.jobs.created}
			{ago(job.created_at)}
		</p>
	</section>

	<h2 class="mt-6 mb-2 text-sm font-medium text-slate-700">{m.jobs.failures}</h2>
	{#if failures.length === 0}
		<p class="text-sm text-slate-500">{m.jobs.noFailures}</p>
	{:else}
		<div class="overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600">
					<tr
						><th class="px-3 py-2">{m.jobs.device}</th><th class="px-3 py-2">{m.jobs.error}</th><th
							class="px-3 py-2">{m.events.when}</th
						></tr
					>
				</thead>
				<tbody>
					{#each failures as f (f.device_id)}
						<tr class="border-t border-slate-100">
							<td class="px-3 py-1.5 font-mono" data-label={m.jobs.device}
								><a
									href="/devices/{f.device_id}{f.task_id ? `?task=${f.task_id}` : ''}"
									class="text-teal-800 hover:underline">{f.device ?? f.device_id}</a
								></td
							>
							<td class="px-3 py-1.5" data-label={m.jobs.error}>{f.error ?? ''}</td>
							<td class="px-3 py-1.5 text-slate-500" data-label={m.events.when}
								>{ago(f.finished_at)}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
{/if}
