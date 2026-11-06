<script lang="ts">
	import { api, ago, type Job } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import JobProgress from '$lib/components/JobProgress.svelte';
	import { m } from '$lib/messages';
	import { stateColor } from './state';

	let jobs = $state<Job[] | null>(null);
	let error = $state<unknown>(null);

	async function load() {
		try {
			jobs = await api.jobs();
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
		const timer = setInterval(load, 5000);
		return () => clearInterval(timer);
	});
</script>

<div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between md:gap-4">
	<div>
		<h1 class="text-xl font-semibold">{m.jobs.title}</h1>
		<p class="text-sm text-slate-600">{m.jobs.intro}</p>
	</div>
	<a
		href="/jobs/new"
		class="self-start rounded bg-teal-700 px-4 py-2.5 text-sm whitespace-nowrap text-white hover:bg-teal-800 md:self-auto md:py-2"
		>{m.jobs.create}</a
	>
</div>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !jobs}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else if jobs.length === 0}
	<p class="mt-4 text-slate-500">{m.jobs.empty}</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					<th class="px-3 py-2">{m.jobs.name}</th>
					<th class="px-3 py-2">{m.jobs.task}</th>
					<th class="px-3 py-2">{m.jobs.state}</th>
					<th class="w-64 px-3 py-2">{m.jobs.progress}</th>
					<th class="px-3 py-2">{m.jobs.created}</th>
				</tr>
			</thead>
			<tbody>
				{#each jobs as j (j.id)}
					<tr class="border-t border-slate-100 align-top">
						<td class="px-3 py-2">
							<div class="min-w-0">
								<a href="/jobs/{j.id}" class="font-medium text-teal-800 hover:underline">{j.name}</a
								>
								{#if j.reason}<div class="text-xs text-slate-500">{j.reason}</div>{/if}
							</div>
						</td>
						<td class="px-3 py-2" data-label={m.jobs.task}
							>{m.tasks.kinds[j.task.kind] ?? j.task.kind}</td
						>
						<td class="px-3 py-2" data-label={m.jobs.state}
							><span class="rounded px-2 py-0.5 text-xs {stateColor[j.state] ?? ''}">{j.state}</span
							></td
						>
						<td class="px-3 py-2" data-label={m.jobs.progress}>
							<div class="min-w-0 flex-1">
								<JobProgress counts={j.counts} total={j.total} />
								<div class="mt-1 text-xs text-slate-500">
									{m.jobs.ofTotal(
										j.counts.succeeded + j.counts.failed + j.counts.cancelled,
										j.total
									)}
								</div>
							</div>
						</td>
						<td class="px-3 py-2 text-slate-500" data-label={m.jobs.created} title={j.created_at}
							>{ago(j.created_at)}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
