<script lang="ts">
	import { api, ago, type DeviceMetric, type SeriesPoint } from '$lib/api';
	import MetricChart from '$lib/components/MetricChart.svelte';
	import { m } from '$lib/messages';

	let { deviceId }: { deviceId: string } = $props();
	let metrics = $state<DeviceMetric[]>([]);
	let url = $state('');
	let selected = $state('');
	let hours = $state(24);
	let points = $state<SeriesPoint[]>([]);
	let error = $state('');

	$effect(() => {
		api
			.metrics(deviceId)
			.then((list) => {
				metrics = list;
				if (!selected && list.length > 0) selected = list[0].path;
			})
			.catch((e) => (error = String(e)));
		api
			.bulkdataUrl(deviceId)
			.then((r) => (url = r.url))
			.catch(() => (url = ''));
	});

	$effect(() => {
		if (!selected) return;
		api
			.series(deviceId, selected, hours)
			.then((s) => (points = s.points))
			.catch((e) => (error = String(e)));
	});
</script>

{#if url}
	<p class="mt-3 text-sm text-slate-600">
		{m.metrics.bulkdataUrl}: <code class="font-mono text-xs break-all">{url}</code>
	</p>
{/if}
{#if error}<p class="mt-3 text-sm text-red-700">{error}</p>{/if}
{#if metrics.length === 0}
	<p class="mt-3 text-slate-500">{m.metrics.empty}</p>
{:else}
	<div class="mt-3 grid gap-4 lg:grid-cols-3">
		<div class="max-h-[28rem] overflow-y-auto rounded-md border border-slate-200 bg-white">
			<table class="min-w-full text-sm">
				<tbody>
					{#each metrics as mt (mt.path)}
						<tr
							class="cursor-pointer border-t border-slate-100 first:border-t-0 {selected === mt.path
								? 'bg-teal-50'
								: 'hover:bg-slate-50'}"
							onclick={() => (selected = mt.path)}
						>
							<td class="px-3 py-1.5 font-mono text-xs break-all">{mt.path}</td>
							<td class="px-3 py-1.5 text-right tabular-nums" title={ago(mt.last_ts)}
								>{mt.last_value}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<div class="rounded-md border border-slate-200 bg-white p-4 lg:col-span-2">
			<div class="flex flex-wrap items-center gap-3">
				<span class="font-mono text-sm break-all">{selected}</span>
				<select bind:value={hours} class="ml-auto rounded border-slate-300 text-sm">
					{#each [24, 168, 720] as h (h)}<option value={h}>{m.metrics.range[h]}</option>{/each}
				</select>
			</div>
			{#if points.length === 0}
				<p class="mt-4 text-sm text-slate-500">{m.metrics.noData}</p>
			{:else}
				<div class="mt-3"><MetricChart {points} /></div>
				<p class="mt-1 text-xs text-slate-500">{m.metrics.legend}</p>
			{/if}
		</div>
	</div>
{/if}
