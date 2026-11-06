<script lang="ts">
	import { api, ago, type WgHub, type WgNetwork, type WgSummary } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';
	import { errorText, hubDot, shortKey, stateParts, stateText } from '$lib/wireguard';

	let hubs = $state<WgHub[] | null>(null);
	let networks = $state<WgNetwork[] | null>(null);
	// Tunnel states, per network.
	let health = $state<Map<string, WgSummary['networks'][number]>>(new Map());
	let error = $state<unknown>(null);
	let notice = $state('');

	const admin = $derived(session.me?.role === 'admin');

	async function load() {
		try {
			const [h, n, sum] = await Promise.all([api.wgHubs(), api.wgNetworks(), api.wgSummary()]);
			hubs = h;
			networks = n;
			health = new Map(sum.networks.map((x) => [x.id, x]));
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
		const timer = setInterval(load, 10000);
		return () => clearInterval(timer);
	});

	// --- add hub
	let hubOpen = $state(false);
	let hubName = $state('');
	let hubHost = $state('');
	let hubError = $state('');
	let busy = $state(false);

	function openHub() {
		hubName = hubHost = hubError = '';
		hubOpen = true;
	}

	async function addHub(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		hubError = '';
		try {
			await api.createWgHub(hubName, hubHost);
			hubOpen = false;
			await load();
		} catch (err) {
			hubError = errorText(err);
		} finally {
			busy = false;
		}
	}

	// --- hub tokens: token only in this one answer -> dropped when the modal closes.
	let token = $state<{ hub: string; token: string } | null>(null);
	let copied = $state(false);

	async function issueToken(h: WgHub) {
		if (h.token_prefix && !confirm(m.wireguard.confirmReplaceToken(h.name))) return;
		notice = '';
		try {
			const r = await api.issueWgHubToken(h.id);
			copied = false;
			token = { hub: h.name, token: r.token };
			await load();
		} catch (err) {
			notice = errorText(err);
		}
	}

	async function revokeToken(h: WgHub) {
		if (!confirm(m.wireguard.confirmRevokeToken(h.name))) return;
		notice = '';
		try {
			await api.revokeWgHubToken(h.id);
			await load();
		} catch (err) {
			notice = errorText(err);
		}
	}

	async function copyToken() {
		if (!token) return;
		try {
			await navigator.clipboard.writeText(token.token);
			copied = true;
		} catch {
			// No clipboard access -> token on screen, copy by hand.
		}
	}

	// --- add network
	let netOpen = $state(false);
	let netHub = $state('');
	let netName = $state('');
	let prefixMode = $state<'auto' | 'explicit'>('auto');
	let prefixLen = $state(24);
	let prefix = $state('');
	let port = $state<number | null>(null);
	let mtu = $state(1420);
	let netError = $state('');

	function openNetwork() {
		netHub = hubs?.[0]?.id ?? '';
		netName = prefix = netError = '';
		prefixMode = 'auto';
		prefixLen = 24;
		port = null;
		mtu = 1420;
		netOpen = true;
	}

	async function addNetwork(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		netError = '';
		try {
			await api.createWgNetwork({
				hub_id: netHub,
				name: netName,
				...(prefixMode === 'auto' ? { prefix_len: prefixLen } : { ipv4_prefix: prefix.trim() }),
				...(port ? { listen_port: port } : {}),
				mtu
			});
			netOpen = false;
			await load();
		} catch (err) {
			netError = errorText(err);
		} finally {
			busy = false;
		}
	}

	const th = 'px-3 py-2';
	const td = 'px-3 py-2';
	const input = 'mt-1 block w-full rounded border-slate-300 text-sm';
	const button = 'rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2';
	const cancel = 'rounded border border-slate-300 bg-white px-4 py-2.5 hover:bg-slate-50 md:py-2';
	const link = 'text-teal-800 hover:underline';
</script>

<div>
	<h1 class="text-xl font-semibold">{m.wireguard.title}</h1>
	<p class="max-w-4xl text-sm text-slate-600">{m.wireguard.intro}</p>
</div>

{#if notice}<p class="mt-4 rounded bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
		{notice}
	</p>{/if}

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !hubs || !networks}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else}
	<section class="mt-6">
		<div class="flex items-end justify-between gap-4">
			<h2 class="font-semibold">{m.wireguard.hubs}</h2>
			{#if admin}<button onclick={openHub} class={button}>{m.wireguard.addHub}</button>{/if}
		</div>
		{#if hubs.length === 0}
			<p class="mt-2 text-slate-500">{m.wireguard.hubsEmpty}</p>
		{:else}
			<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="stack min-w-full text-sm">
					<thead class="bg-slate-100 text-left text-slate-600">
						<tr>
							<th class={th}>{m.wireguard.name}</th>
							<th class={th}>{m.wireguard.endpoint}</th>
							<th class={th}>{m.wireguard.publicKey}</th>
							<th class={th}>{m.wireguard.lastSeen}</th>
							<th class={th}>{m.wireguard.networks}</th>
							<th class={th}>{m.wireguard.token}</th>
							{#if admin}<th class={th}></th>{/if}
						</tr>
					</thead>
					<tbody>
						{#each hubs as h (h.id)}
							<tr class="border-t border-slate-100 align-top">
								<td class="{td} font-medium">{h.name}</td>
								<td class="{td} font-mono" data-label={m.wireguard.endpoint}>{h.endpoint_host}</td>
								<td class={td} data-label={m.wireguard.publicKey}>
									{#if h.public_key}<span class="font-mono" title={h.public_key}
											>{shortKey(h.public_key)}</span
										>{:else}<span class="text-slate-500">{m.wireguard.noPublicKey}</span>{/if}
								</td>
								<td class={td} data-label={m.wireguard.lastSeen}>
									<div class="min-w-0">
										<span class="inline-flex items-center gap-1.5" title={h.last_seen_at ?? ''}
											><span class="h-2 w-2 rounded-full {hubDot(h.last_seen_at)}"></span>{ago(
												h.last_seen_at,
												m.wireguard.never
											)}</span
										>
										{#if h.version || h.last_seen_ip}<div class="text-xs text-slate-500">
												{[h.version, h.last_seen_ip].filter(Boolean).join(' · ')}
											</div>{/if}
									</div>
								</td>
								<td class={td} data-label={m.wireguard.networks}>{h.networks}</td>
								<td class={td} data-label={m.wireguard.token}>
									{#if h.token_prefix}<span class="font-mono" title={h.token_created_at ?? ''}
											>{h.token_prefix}…</span
										>{:else}<span class="text-slate-500">{m.wireguard.noToken}</span>{/if}
								</td>
								{#if admin}
									<td class="{td} text-right whitespace-nowrap">
										<button onclick={() => issueToken(h)} class="{link} py-2 md:py-0"
											>{m.wireguard.issueToken}</button
										>
										{#if h.token_prefix}<button
												onclick={() => revokeToken(h)}
												class="ml-3 py-2 text-red-700 hover:underline md:py-0"
												>{m.wireguard.revokeToken}</button
											>{/if}
									</td>
								{/if}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	<section class="mt-8">
		<div class="flex items-end justify-between gap-4">
			<h2 class="font-semibold">{m.wireguard.networks}</h2>
			{#if admin && hubs.length > 0}<button onclick={openNetwork} class={button}
					>{m.wireguard.addNetwork}</button
				>{/if}
		</div>
		{#if networks.length === 0}
			<p class="mt-2 text-slate-500">{m.wireguard.networksEmpty}</p>
		{:else}
			<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="stack min-w-full text-sm">
					<thead class="bg-slate-100 text-left text-slate-600">
						<tr>
							<th class={th}>{m.wireguard.name}</th>
							<th class={th}>{m.wireguard.hub}</th>
							<th class={th}>{m.wireguard.prefix}</th>
							<th class={th}>{m.wireguard.hubAddress}</th>
							<th class={th}>{m.wireguard.port}</th>
							<th class={th}>{m.wireguard.mtu}</th>
							<th class={th}>{m.wireguard.members}</th>
						</tr>
					</thead>
					<tbody>
						{#each networks as n (n.id)}
							{@const states = health.get(n.id)}
							<tr class="border-t border-slate-100 align-top">
								<td class={td}>
									<a
										href="/wireguard/networks/{n.id}"
										class="font-medium text-teal-800 hover:underline">{n.name}</a
									>
								</td>
								<td class={td} data-label={m.wireguard.hub}>{n.hub.name}</td>
								<td class="{td} font-mono" data-label={m.wireguard.prefix}>{n.ipv4_prefix}</td>
								<td class="{td} font-mono" data-label={m.wireguard.hubAddress}>{n.hub_address}</td>
								<td class={td} data-label={m.wireguard.port}>{n.listen_port}</td>
								<td class={td} data-label={m.wireguard.mtu}>{n.mtu}</td>
								<td class={td} data-label={m.wireguard.members}>
									<div class="min-w-0">
										{m.wireguard.memberCounts(n.members.device, n.members.client)}
										{#if n.members.revoked > 0}<span class="text-slate-400">
												· {m.wireguard.revokedCount(n.members.revoked)}</span
											>{/if}
										{#if states}
											<div class="text-xs">
												{#each stateParts(states.device, states.client) as p, i (p.state)}{#if i > 0}
														·
													{/if}<span class={stateText[p.state]}
														>{p.n} {m.wireguard.stateNames[p.state]}</span
													>{/each}
											</div>
										{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
{/if}

{#if hubOpen}
	<Modal title={m.wireguard.addHub} onclose={() => (hubOpen = false)}>
		<form onsubmit={addHub} class="max-w-md space-y-4">
			<label class="block"
				>{m.wireguard.name}<input
					bind:value={hubName}
					required
					maxlength="64"
					class={input}
				/></label
			>
			<label class="block"
				>{m.wireguard.endpointHost}<input
					bind:value={hubHost}
					required
					placeholder="hub.example.net"
					class="{input} font-mono"
				/><span class="mt-1 block text-xs text-slate-500">{m.wireguard.endpointHostHint}</span
				></label
			>
			{#if hubError}<p class="text-red-700" role="alert">{hubError}</p>{/if}
			<div class="flex gap-2">
				<button disabled={busy} class="{button} disabled:opacity-50"
					>{busy ? m.wireguard.creating : m.wireguard.create}</button
				>
				<button type="button" onclick={() => (hubOpen = false)} class={cancel}
					>{m.common.cancel}</button
				>
			</div>
		</form>
	</Modal>
{/if}

{#if token}
	<Modal title={m.wireguard.tokenTitle(token.hub)} onclose={() => (token = null)}>
		<div class="space-y-4">
			<p
				class="rounded border border-amber-300 bg-amber-50 p-3 font-medium text-amber-900"
				role="alert"
			>
				{m.wireguard.tokenOnce}
			</p>
			<p class="text-slate-600">{m.wireguard.tokenUse}</p>
			<p class="rounded bg-slate-50 p-3 font-mono break-all select-all">{token.token}</p>
			<div class="flex gap-2">
				<button type="button" onclick={copyToken} class={button}
					>{copied ? m.wireguard.copied : m.wireguard.copy}</button
				>
				<button type="button" onclick={() => (token = null)} class={cancel}
					>{m.wireguard.done}</button
				>
			</div>
		</div>
	</Modal>
{/if}

{#if netOpen && hubs}
	<Modal title={m.wireguard.addNetwork} onclose={() => (netOpen = false)}>
		<form onsubmit={addNetwork} class="max-w-md space-y-4">
			<label class="block"
				>{m.wireguard.hub}<select bind:value={netHub} required class={input}>
					{#each hubs as h (h.id)}<option value={h.id}>{h.name} ({h.endpoint_host})</option>{/each}
				</select></label
			>
			<label class="block"
				>{m.wireguard.name}<input
					bind:value={netName}
					required
					maxlength="64"
					class={input}
				/></label
			>
			<fieldset class="space-y-2">
				<legend>{m.wireguard.prefixChoice}</legend>
				<label class="flex flex-wrap items-center gap-2"
					><input type="radio" bind:group={prefixMode} value="auto" />{m.wireguard.prefixAuto}
					<span class="font-mono">/</span><input
						type="number"
						min="16"
						max="29"
						bind:value={prefixLen}
						disabled={prefixMode !== 'auto'}
						class="w-20 rounded border-slate-300 text-sm"
					/></label
				>
				<p class="pl-6 text-xs text-slate-500">{m.wireguard.prefixLengthHint}</p>
				<label class="flex flex-wrap items-center gap-2"
					><input type="radio" bind:group={prefixMode} value="explicit" />{m.wireguard
						.prefixExplicit}<input
						bind:value={prefix}
						disabled={prefixMode !== 'explicit'}
						required={prefixMode === 'explicit'}
						placeholder="10.77.4.0/24"
						class="w-44 rounded border-slate-300 font-mono text-sm"
					/></label
				>
			</fieldset>
			<label class="block"
				>{m.wireguard.listenPort}<input
					type="number"
					min="1"
					max="65535"
					bind:value={port}
					placeholder="51820"
					class={input}
				/><span class="mt-1 block text-xs text-slate-500">{m.wireguard.listenPortHint}</span></label
			>
			<label class="block"
				>{m.wireguard.mtu}<input
					type="number"
					min="1280"
					max="1500"
					bind:value={mtu}
					required
					class={input}
				/></label
			>
			{#if netError}<p class="text-red-700" role="alert">{netError}</p>{/if}
			<div class="flex gap-2">
				<button disabled={busy} class="{button} disabled:opacity-50"
					>{busy ? m.wireguard.creating : m.wireguard.create}</button
				>
				<button type="button" onclick={() => (netOpen = false)} class={cancel}
					>{m.common.cancel}</button
				>
			</div>
		</form>
	</Modal>
{/if}
