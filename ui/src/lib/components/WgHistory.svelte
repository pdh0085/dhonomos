<script lang="ts">
	import { api, bitRate, type SeriesPoint } from '$lib/api';
	import MetricChart from '$lib/components/MetricChart.svelte';
	import { m } from '$lib/messages';
	import { errorText } from '$lib/wireguard';

	/**
	 * Tunnel history of a device member, from server samples of its hub reports.
	 * `deviceId`: record that owns the member (-> the samples).
	 */
	let { deviceId, networkId }: { deviceId: string; networkId: string } = $props();

	let days7 = $state(false);
	let connected = $state<SeriesPoint[] | null>(null);
	let rx = $state<SeriesPoint[]>([]);
	let tx = $state<SeriesPoint[]>([]);
	let error = $state('');

	const path = (what: string) => `Dhonomos.WireGuard.${networkId.replaceAll('-', '')}.${what}`;

	$effect(() => {
		const [hours, step] = days7 ? [168, 3600] : [24, 300];
		let stale = false;
		error = '';
		Promise.all(
			['Connected', 'RxRate', 'TxRate'].map((w) => api.series(deviceId, path(w), hours, step))
		)
			.then(([c, r, t]) => {
				if (stale) return;
				connected = c.points;
				rx = r.points;
				tx = t.points;
			})
			.catch((e) => {
				if (!stale) error = errorText(e);
			});
		return () => {
			stale = true;
		};
	});

	const availability = $derived.by(() => {
		if (!connected || connected.length === 0) return null;
		const mean = connected.reduce((sum, p) => sum + p.avg, 0) / connected.length;
		return Math.round(mean * 100);
	});
</script>

{#snippet rate(label: string, pts: SeriesPoint[])}
	<div>
		<div class="text-slate-500">{label}</div>
		{#if pts.length === 0}
			<p class="text-slate-400">{m.wireguard.historyNoData}</p>
		{:else}
			<MetricChart points={pts} format={bitRate} />
		{/if}
	</div>
{/snippet}

<div class="mt-2 space-y-3">
	<div class="flex flex-wrap items-center justify-between gap-2">
		<span class="text-slate-700">
			{#if !connected}
				{m.common.loading}
			{:else if availability === null}
				{m.wireguard.availabilityNoData}
			{:else}
				{m.wireguard.availability(availability, days7)}
			{/if}
		</span>
		<label class="flex items-center gap-2"
			><input type="checkbox" bind:checked={days7} class="rounded border-slate-300" />{m.wireguard
				.last7Days}</label
		>
	</div>
	{#if error}<p class="text-red-700" role="alert">{error}</p>{/if}
	{#if connected && connected.length === 0 && rx.length === 0 && tx.length === 0}
		<p class="text-slate-500">{m.wireguard.historyNoData}</p>
	{:else if connected}
		<div>
			<div class="text-slate-500">{m.wireguard.connectedChart}</div>
			<MetricChart points={connected} domain={[0, 1]} />
		</div>
		<div class="grid gap-3 md:grid-cols-2">
			{@render rate(m.wireguard.rxRate, rx)}
			{@render rate(m.wireguard.txRate, tx)}
		</div>
	{/if}
	<p class="text-slate-500">{m.wireguard.historyHint}</p>
</div>
