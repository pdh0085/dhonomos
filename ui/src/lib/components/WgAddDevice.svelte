<script lang="ts">
	import { api, type Device, type WgSecretAnswer } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';
	import { errorText } from '$lib/wireguard';

	// `ondone` gets the answer: holds the PSK if one was made.
	let {
		network,
		onclose,
		ondone
	}: { network: string; onclose: () => void; ondone: (answer: WgSecretAnswer) => void } = $props();

	let query = $state('');
	let results = $state<Device[] | null>(null);
	let searchError = $state('');
	let picked = $state<Device | null>(null);
	let name = $state('');
	let keyMode = $state<'device' | 'server'>('device');
	let sites = $state('');
	let usePsk = $state(false);
	let error = $state('');
	let busy = $state(false);

	const label = (d: Device) => d.serial_number ?? d.endpoint_id ?? d.id;

	async function search(e: SubmitEvent) {
		e.preventDefault();
		searchError = '';
		try {
			results = (await api.devices({ q: query }, 10)).items;
		} catch (err) {
			searchError = errorText(err);
		}
	}

	/** 1 prefix per line; text after the 1st space = description. */
	function sitePrefixes() {
		return sites
			.split('\n')
			.map((l) => l.trim())
			.filter(Boolean)
			.map((l) => {
				const at = l.search(/\s/);
				return at < 0
					? { prefix: l }
					: { prefix: l.slice(0, at), description: l.slice(at + 1).trim() };
			});
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!picked) return;
		busy = true;
		error = '';
		try {
			const prefixes = sitePrefixes();
			const answer = await api.createWgMember(network, {
				kind: 'device',
				device_id: picked.id,
				...(name.trim() ? { name: name.trim() } : {}),
				key_mode: keyMode,
				...(usePsk ? { preshared_key_enabled: true } : {}),
				...(prefixes.length ? { site_prefixes: prefixes } : {})
			});
			ondone(answer);
		} catch (err) {
			error = errorText(err);
		} finally {
			busy = false;
		}
	}

	const input = 'rounded border-slate-300 text-sm';
	const button = 'rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2';
</script>

<Modal title={m.wireguard.addDevice} {onclose}>
	<form onsubmit={search} class="flex flex-wrap items-end gap-2">
		<label class="w-full grow md:w-auto"
			>{m.wireguard.search}<input
				bind:value={query}
				placeholder={m.wireguard.searchHint}
				class="{input} mt-1 block w-full"
			/></label
		>
		<button class={button}>{m.wireguard.search}</button>
	</form>
	{#if searchError}<p class="mt-2 text-red-700" role="alert">{searchError}</p>{/if}
	{#if results}
		{#if results.length === 0}
			<p class="mt-3 text-slate-500">{m.wireguard.noDevices}</p>
		{:else}
			<ul class="mt-3 divide-y divide-slate-100 rounded border border-slate-200">
				{#each results as d (d.id)}
					<li class="flex items-center justify-between gap-3 px-3 py-2">
						<div class="min-w-0 [overflow-wrap:anywhere] md:[overflow-wrap:normal]">
							<span class="font-mono">{label(d)}</span>
							<span class="ml-2 text-slate-600">{d.model_name ?? d.product_class}</span>
							<span class="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-xs uppercase"
								>{d.protocol}</span
							>
						</div>
						{#if picked?.id === d.id}
							<span class="text-xs font-medium text-teal-800">{m.wireguard.picked}</span>
						{:else}
							<button
								type="button"
								onclick={() => (picked = d)}
								class="shrink-0 py-2 text-teal-800 hover:underline md:py-0"
								>{m.wireguard.pick}</button
							>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	{/if}

	{#if picked}
		<form onsubmit={submit} class="mt-5 max-w-lg space-y-4 border-t border-slate-200 pt-4">
			<p>
				<span class="text-slate-600">{m.wireguard.device}:</span>
				<span class="font-mono break-all md:break-normal">{label(picked)}</span>
			</p>
			<label class="block"
				>{m.wireguard.memberName}<input
					bind:value={name}
					maxlength="64"
					class="{input} mt-1 block w-full"
				/><span class="mt-1 block text-xs text-slate-500">{m.wireguard.memberNameHint}</span></label
			>
			<label class="block"
				>{m.wireguard.keyMode}<select bind:value={keyMode} class="{input} mt-1 block w-full">
					<option value="device">{m.wireguard.keyModes.device}</option>
					<option value="server">{m.wireguard.keyModes.server}</option>
				</select></label
			>
			<label class="block"
				><span class="flex items-center gap-2"
					><input type="checkbox" bind:checked={usePsk} class="rounded border-slate-300" />{m
						.wireguard.usePsk}</span
				><span class="mt-1 block text-xs text-slate-500">{m.wireguard.usePskHint}</span></label
			>
			<label class="block"
				>{m.wireguard.sitePrefixes}<textarea
					bind:value={sites}
					rows="3"
					placeholder="192.168.10.0/24 office LAN"
					class="{input} mt-1 block w-full font-mono"
				></textarea><span class="mt-1 block text-xs text-slate-500"
					>{m.wireguard.sitePrefixesHint}</span
				></label
			>
			{#if error}<p class="text-red-700" role="alert">{error}</p>{/if}
			<div class="flex gap-2">
				<button disabled={busy} class="{button} disabled:opacity-50"
					>{busy ? m.wireguard.adding : m.wireguard.add}</button
				>
				<button
					type="button"
					onclick={onclose}
					class="rounded border border-slate-300 bg-white px-4 py-2.5 hover:bg-slate-50 md:py-2"
					>{m.common.cancel}</button
				>
			</div>
		</form>
	{/if}
</Modal>
