<script lang="ts">
	import { api, ago, type WifiView } from '$lib/api';
	import { m } from '$lib/messages';

	let { deviceId, root }: { deviceId: string; root: string } = $props();
	let wifi = $state<WifiView | null>(null);
	let notice = $state('');

	async function load() {
		try {
			wifi = await api.wifi(deviceId);
		} catch (e) {
			notice = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		load();
		const timer = setInterval(load, 10000);
		return () => clearInterval(timer);
	});

	async function queue(task: { kind: string; payload?: unknown }) {
		try {
			await api.createTask(deviceId, task);
			notice = m.wifi.queued;
		} catch (e) {
			notice = e instanceof Error ? e.message : String(e);
		}
	}

	const refresh = () =>
		queue({
			kind: 'get_parameter_values',
			payload: {
				names: [
					root === 'InternetGatewayDevice' ? 'InternetGatewayDevice.LANDevice.' : 'Device.WiFi.'
				]
			}
		});
	const scan = () => queue({ kind: 'diagnostic', payload: { test: 'wifi_neighbors' } });
	const cell = 'px-3 py-1.5';
</script>

<div class="mt-3 flex flex-wrap gap-2">
	<button
		onclick={refresh}
		class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
		>{m.wifi.refresh}</button
	>
	{#if root !== 'InternetGatewayDevice'}
		<button
			onclick={scan}
			class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
			>{m.wifi.scan}</button
		>
	{/if}
</div>
{#if notice}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm">{notice}</p>{/if}

{#if wifi}
	{#if wifi.radios.length === 0 && wifi.networks.length === 0}
		<p class="mt-3 text-slate-500">{m.wifi.none}</p>
	{/if}
	{#if wifi.radios.length > 0}
		<h3 class="mt-4 text-sm font-medium text-slate-700">{m.wifi.radios}</h3>
		<div class="mt-1 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600"
					><tr
						><th class={cell}>{m.wifi.band}</th><th class={cell}>{m.wifi.channel}</th><th
							class={cell}>{m.wifi.bandwidth}</th
						><th class={cell}>{m.wifi.noise}</th><th class={cell}>{m.devices.status}</th></tr
					></thead
				>
				<tbody>
					{#each wifi.radios as r (r.id)}
						<tr class="border-t border-slate-100"
							><td class={cell} data-label={m.wifi.band}>{r.band ?? m.common.none}</td><td
								class={cell}
								data-label={m.wifi.channel}>{r.channel ?? m.common.none}</td
							><td class={cell} data-label={m.wifi.bandwidth}>{r.bandwidth ?? m.common.none}</td><td
								class={cell}
								data-label={m.wifi.noise}>{r.noise_dbm ?? m.common.none}</td
							><td class={cell} data-label={m.devices.status}>{r.status ?? m.common.none}</td></tr
						>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
	{#each wifi.networks as n, i (i)}
		<h3 class="mt-4 text-sm font-medium break-words text-slate-700">
			{n.ssid ?? m.common.none}
			<span class="font-normal text-slate-500"
				>{n.bssid ?? ''}
				{n.security ?? ''} · {m.wifi.stationCount(n.stations.length)}</span
			>
		</h3>
		{#if n.stations.length > 0}
			<div class="mt-1 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="stack min-w-full text-sm">
					<thead class="bg-slate-100 text-left text-slate-600"
						><tr
							><th class={cell}>MAC</th><th class={cell}>{m.wifi.signal}</th><th class={cell}
								>{m.wifi.rate}</th
							></tr
						></thead
					>
					<tbody>
						{#each n.stations as st, j (j)}
							<tr class="border-t border-slate-100"
								><td class="{cell} font-mono" data-label="MAC">{st.mac ?? m.common.none}</td><td
									class={cell}
									data-label={m.wifi.signal}>{st.signal_dbm ?? m.common.none}</td
								><td class={cell} data-label={m.wifi.rate}>{st.down_kbps ?? m.common.none}</td></tr
							>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{/each}
	<h3 class="mt-4 text-sm font-medium text-slate-700">
		{m.wifi.neighbors}
		{#if wifi.neighbor_scan}<span class="font-normal text-slate-500"
				>· {m.wifi.scanned} {ago(wifi.neighbor_scan.at)}</span
			>{/if}
	</h3>
	{#if !wifi.neighbor_scan?.neighbors?.length}
		<p class="mt-1 text-sm text-slate-500">{m.wifi.noScan}</p>
	{:else}
		<div class="mt-1 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600"
					><tr
						><th class={cell}>SSID</th><th class={cell}>BSSID</th><th class={cell}>{m.wifi.band}</th
						><th class={cell}>{m.wifi.channel}</th><th class={cell}>{m.wifi.signal}</th></tr
					></thead
				>
				<tbody>
					{#each wifi.neighbor_scan.neighbors as nb, k (k)}
						<tr class="border-t border-slate-100"
							><td class={cell}>{nb.ssid ?? m.common.none}</td><td
								class="{cell} font-mono"
								data-label="BSSID">{nb.bssid ?? ''}</td
							><td class={cell} data-label={m.wifi.band}>{nb.band ?? ''}</td><td
								class={cell}
								data-label={m.wifi.channel}>{nb.channel ?? ''}</td
							><td class={cell} data-label={m.wifi.signal}>{nb.signal_dbm ?? ''}</td></tr
						>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
{/if}
