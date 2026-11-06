<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		api,
		ago,
		bytes,
		saveText,
		type WgHub,
		type WgMember,
		type WgNetwork,
		type WgSecretAnswer
	} from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import WgAddDevice from '$lib/components/WgAddDevice.svelte';
	import WgSecret from '$lib/components/WgSecret.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';
	import {
		deviceStateColor,
		errorText,
		handshakeDot,
		stateDot,
		tunnelState,
		type WgState
	} from '$lib/wireguard';

	const id = $derived(page.params.id ?? '');
	// In URL -> view survives reload + can be linked.
	const showRevoked = $derived(page.url.searchParams.get('revoked') === '1');
	const admin = $derived(session.me?.role === 'admin');

	let network = $state<WgNetwork | null>(null);
	let hub = $state<WgHub | null>(null);
	let members = $state<WgMember[] | null>(null);
	let total = $state(0);
	let error = $state<unknown>(null);
	let notice = $state('');
	let info = $state('');

	async function load() {
		try {
			const [n, list, hubs] = await Promise.all([
				api.wgNetwork(id),
				api.wgMembers(id, showRevoked),
				api.wgHubs()
			]);
			network = n;
			hub = hubs.find((h) => h.id === n.hub.id) ?? null;
			members = list.items;
			total = list.total;
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		void [id, showRevoked];
		load();
		const timer = setInterval(load, 10000);
		return () => clearInterval(timer);
	});

	function toggleRevoked() {
		const url = new URL(page.url);
		if (showRevoked) url.searchParams.delete('revoked');
		else url.searchParams.set('revoked', '1');
		goto(url, { replaceState: true, keepFocus: true, noScroll: true });
	}

	// Answer of create or re-key. Holds private key or PSK:
	// shown in one modal, dropped on close.
	let secret = $state<WgSecretAnswer | null>(null);

	function showSecret(answer: WgSecretAnswer) {
		if (answer.config || answer.preshared_key) secret = answer;
	}

	async function configuration(mb: WgMember) {
		notice = '';
		try {
			const c = await api.wgMemberConfig(mb.id);
			saveText(c.config, c.config_filename);
		} catch (e) {
			notice = errorText(e);
		}
	}

	async function rekey(mb: WgMember) {
		if (!confirm(m.wireguard.confirmRekey(mb.name))) return;
		notice = '';
		try {
			showSecret(await api.rekeyWgMember(mb.id));
			await load();
		} catch (e) {
			notice = errorText(e);
		}
	}

	async function rotateKey(mb: WgMember) {
		if (!confirm(m.wireguard.confirmRotateKey)) return;
		notice = info = '';
		try {
			await api.rotateWgMemberKey(mb.id);
			await load();
		} catch (e) {
			notice = errorText(e);
		}
	}

	// --- state filter: live members by tunnel state (revoked: always listed as is)
	const CHIPS = ['', 'connected', 'idle', 'stale', 'never'] as const;
	let stateFilter = $state<(typeof CHIPS)[number]>('');
	const stateOf = (mb: WgMember): WgState =>
		tunnelState(mb.hub_status?.latest_handshake, hub?.last_seen_at);
	const chipCounts = $derived.by(() => {
		const counts: Record<string, number> = { '': 0, connected: 0, idle: 0, stale: 0, never: 0 };
		for (const mb of members ?? []) {
			if (mb.revoked_at) continue;
			counts['']++;
			const st = stateOf(mb);
			if (st in counts) counts[st]++;
		}
		return counts;
	});
	const shown = $derived(
		(members ?? []).filter(
			(mb) => stateFilter === '' || mb.revoked_at || stateOf(mb) === stateFilter
		)
	);

	// Live device members for "rotate all" (API counts again).
	const liveDevices = $derived(
		(members ?? []).filter((mb) => mb.kind === 'device' && !mb.revoked_at).length
	);

	async function rotateAll() {
		notice = info = '';
		if (liveDevices === 0) {
			info = m.wireguard.rotateAllNone;
			return;
		}
		if (!confirm(m.wireguard.confirmRotateAll(liveDevices))) return;
		try {
			const r = await api.rotateWgNetworkKeys(id);
			info = m.wireguard.rotateAllDone(r.requested);
			await load();
		} catch (e) {
			notice = errorText(e);
		}
	}

	// --- revoke
	let revoking = $state<WgMember | null>(null);
	let reason = $state('');
	let revokeError = $state('');
	let busy = $state(false);

	function openRevoke(mb: WgMember) {
		revoking = mb;
		reason = revokeError = '';
	}

	async function revoke(e: SubmitEvent) {
		e.preventDefault();
		if (!revoking) return;
		busy = true;
		revokeError = '';
		try {
			await api.revokeWgMember(revoking.id, reason.trim() || undefined);
			revoking = null;
			await load();
		} catch (err) {
			revokeError = errorText(err);
		} finally {
			busy = false;
		}
	}

	// --- add client
	let clientOpen = $state(false);
	let clientName = $state('');
	let owner = $state<'me' | 'server'>('me');
	let clientPsk = $state(false);
	let clientError = $state('');

	function openClient() {
		clientName = clientError = '';
		clientPsk = false;
		// No own account (open mode, shared API token) -> can only add server clients.
		owner = admin && ['open', 'token'].includes(session.me?.via ?? '') ? 'server' : 'me';
		clientOpen = true;
	}

	async function addClient(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		clientError = '';
		try {
			const answer = await api.createWgMember(id, {
				kind: 'client',
				name: clientName,
				...(admin && owner === 'server' ? { user_id: null } : {}),
				...(clientPsk ? { preshared_key_enabled: true } : {})
			});
			clientOpen = false;
			showSecret(answer);
			await load();
		} catch (err) {
			clientError = errorText(err);
		} finally {
			busy = false;
		}
	}

	let deviceOpen = $state(false);

	const th = 'px-3 py-2';
	const td = 'px-3 py-2';
	const button = 'rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2';
	const cancel = 'rounded border border-slate-300 bg-white px-4 py-2.5 hover:bg-slate-50 md:py-2';
	const link = 'text-teal-800 hover:underline';
</script>

<a href="/wireguard" class="text-sm text-teal-800 hover:underline">← {m.wireguard.back}</a>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !network || !members}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else}
	<div class="mt-2 flex flex-wrap items-end justify-between gap-4">
		<div class="min-w-0">
			<h1 class="text-xl font-semibold break-words">{network.name}</h1>
			<dl class="mt-1 flex flex-wrap gap-x-6 gap-y-1 text-sm text-slate-600">
				<div>
					<dt class="inline">{m.wireguard.hub}:</dt>
					<dd class="inline">
						{network.hub.name}
						<span class="font-mono break-all md:break-normal"
							>{network.hub.endpoint_host}:{network.listen_port}</span
						>
					</dd>
				</div>
				<div>
					<dt class="inline">{m.wireguard.prefix}:</dt>
					<dd class="inline font-mono">{network.ipv4_prefix}</dd>
				</div>
				<div>
					<dt class="inline">{m.wireguard.hubAddress}:</dt>
					<dd class="inline font-mono">{network.hub_address}</dd>
				</div>
				<div>
					<dt class="inline">{m.wireguard.mtu}:</dt>
					<dd class="inline">{network.mtu}</dd>
				</div>
			</dl>
		</div>
		<div class="flex flex-wrap gap-2">
			<button onclick={openClient} class={button}>{m.wireguard.addClient}</button>
			<button onclick={() => (deviceOpen = true)} class={button}>{m.wireguard.addDevice}</button>
			{#if admin}
				<button onclick={rotateAll} class={cancel}>{m.wireguard.rotateAll}</button>
			{/if}
		</div>
	</div>

	{#if notice}<p class="mt-4 rounded bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
			{notice}
		</p>{/if}
	{#if info}<p class="mt-4 rounded bg-teal-50 px-3 py-2 text-sm text-teal-900" role="status">
			{info}
		</p>{/if}

	<div class="mt-6 flex items-center justify-between gap-4">
		<h2 class="font-semibold">{m.wireguard.members}</h2>
		<label class="flex items-center gap-2 text-sm text-slate-600"
			><input
				type="checkbox"
				checked={showRevoked}
				onchange={toggleRevoked}
				class="rounded border-slate-300"
			/>{m.wireguard.showRevoked}</label
		>
	</div>

	{#if members.length > 0}
		<div class="mt-2 flex flex-wrap gap-2 text-sm" role="group">
			{#each CHIPS as chip (chip)}
				<button
					onclick={() => (stateFilter = chip)}
					aria-pressed={stateFilter === chip}
					class="inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 md:py-0.5 {stateFilter ===
					chip
						? 'border-teal-700 bg-teal-50 text-teal-900'
						: 'border-slate-300 bg-white text-slate-700 hover:bg-slate-50'}"
					>{#if chip}<span class="h-2 w-2 rounded-full {stateDot[chip]}"></span>{/if}{m.wireguard
						.stateChips[chip]}
					<span class="tabular-nums text-slate-500">{chipCounts[chip]}</span></button
				>
			{/each}
		</div>
	{/if}

	{#if members.length === 0}
		<p class="mt-2 text-slate-500">{m.wireguard.membersEmpty}</p>
	{:else if shown.length === 0}
		<p class="mt-2 text-slate-500">{m.wireguard.noneInState}</p>
	{:else}
		<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600">
					<tr>
						<th class={th}>{m.wireguard.name}</th>
						<th class={th}>{m.wireguard.kind}</th>
						<th class={th}>{m.wireguard.address}</th>
						<th class={th}>{m.wireguard.details}</th>
						<th class={th}>{m.wireguard.tunnel}</th>
						<th class={th}>{m.wireguard.device}</th>
						<th class={th}></th>
					</tr>
				</thead>
				<tbody>
					{#each shown as mb (mb.id)}
						{@const hs = mb.hub_status}
						{@const ds = mb.device_status}
						{@const silent = !mb.revoked_at && stateOf(mb) === 'unknown'}
						<tr
							class="border-t border-slate-100 align-top {mb.revoked_at
								? 'bg-slate-50 text-slate-400'
								: ''}"
						>
							<td class={td}>
								<div class="min-w-0">
									<span class="font-medium">{mb.name}</span>
									{#if mb.revoked_at}<div class="text-xs" title={mb.revoked_at}>
											{m.wireguard.revoked(ago(mb.revoked_at), mb.revoked_reason)}
										</div>{/if}
								</div>
							</td>
							<td class={td} data-label={m.wireguard.kind}>
								<div class="min-w-0">
									<span
										class="rounded px-2 py-0.5 text-xs {mb.kind === 'device'
											? 'bg-sky-100 text-sky-900'
											: 'bg-violet-100 text-violet-900'}"
										>{m.wireguard.kinds[mb.kind] ?? mb.kind}</span
									>
									{#if mb.preshared_key_enabled}<span
											class="ml-1 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700"
											title={m.wireguard.pskBadgeTitle}>{m.wireguard.pskBadge}</span
										>{/if}
								</div>
							</td>
							<td class="{td} font-mono" data-label={m.wireguard.address}>{mb.address}</td>
							<td class={td} data-label={m.wireguard.details}>
								<div class="min-w-0">
									{#if mb.kind === 'device'}
										{#if mb.device_id}<a href="/devices/{mb.device_id}" class={link}>{mb.name}</a
											>{/if}
										{#if mb.site_prefixes.length > 0}<div
												class="font-mono text-xs"
												title={mb.site_prefixes
													.map((p) => (p.description ? `${p.prefix} ${p.description}` : p.prefix))
													.join('\n')}
											>
												{mb.site_prefixes.map((p) => p.prefix).join(', ')}
											</div>{/if}
									{:else}
										<span class={mb.revoked_at ? '' : 'text-slate-600'}
											>{mb.user_id ? m.wireguard.account : m.wireguard.serverClient}</span
										>
									{/if}
								</div>
							</td>
							<td class={td} data-label={m.wireguard.tunnel}>
								<div class="min-w-0">
									<span class="inline-flex items-center gap-1.5" title={hs?.latest_handshake ?? ''}
										><span
											class="h-2 w-2 rounded-full {silent
												? stateDot.unknown
												: handshakeDot(hs?.latest_handshake)}"
										></span>{ago(hs?.latest_handshake, m.wireguard.never)}</span
									>
									{#if silent}<div
											class="text-xs text-slate-500"
											title={m.wireguard.hubSilentTitle}
										>
											{m.wireguard.hubSilent}
										</div>{/if}
									{#if hs}
										{#if hs.endpoint}<div class="font-mono text-xs text-slate-500">
												{hs.endpoint}
											</div>{/if}
										<div class="text-xs text-slate-500">
											↓ {bytes(hs.rx_bytes)} ↑ {bytes(hs.tx_bytes)}
										</div>
									{/if}
								</div>
							</td>
							<td class={td} data-label={m.wireguard.device}>
								{#if ds}
									<div class="min-w-0">
										<span
											class="rounded px-2 py-0.5 text-xs {deviceStateColor[ds.state] ??
												'bg-slate-100'}"
											title={ds.detail ?? ''}>{m.wireguard.states[ds.state] ?? ds.state}</span
										>
										{#if ds.detail && ds.state !== 'applied'}<div
												class="mt-1 max-w-xs text-xs break-words text-slate-600"
											>
												{ds.detail}
											</div>{/if}
										{#if ds.checked_at}<div class="text-xs text-slate-500" title={ds.checked_at}>
												{m.wireguard.checked(ago(ds.checked_at))}
											</div>{/if}
										{#if mb.rotate_requested_at}<div
												class="text-xs text-slate-500"
												title={mb.rotate_requested_at}
											>
												{m.wireguard.rotateRequested(ago(mb.rotate_requested_at))}
											</div>{/if}
									</div>
								{:else if mb.kind === 'device'}
									<span class="text-slate-400">{m.common.none}</span>
								{/if}
							</td>
							<td class="{td} text-right whitespace-nowrap">
								{#if !mb.revoked_at}
									{#if mb.kind === 'client'}
										<button
											onclick={() => configuration(mb)}
											title={m.wireguard.configurationHint}
											class="{link} py-2 md:py-0">{m.wireguard.configuration}</button
										>
										<button onclick={() => rekey(mb)} class="{link} ml-3 py-2 md:py-0"
											>{m.wireguard.rekey}</button
										>
									{:else}
										<button onclick={() => rotateKey(mb)} class="{link} py-2 md:py-0"
											>{m.wireguard.rotateKey}</button
										>
									{/if}
									<button
										onclick={() => openRevoke(mb)}
										class="ml-3 py-2 text-red-700 hover:underline md:py-0"
										>{m.wireguard.revoke}</button
									>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		{#if total > members.length}<p class="mt-2 text-xs text-slate-500">
				{m.wireguard.shown(members.length, total)}
			</p>{/if}
	{/if}
{/if}

{#if revoking}
	<Modal title={m.wireguard.revokeTitle(revoking.name)} onclose={() => (revoking = null)}>
		<form onsubmit={revoke} class="max-w-md space-y-4">
			<p class="text-slate-600">{m.wireguard.revokeIntro}</p>
			<label class="block"
				>{m.wireguard.reason}<input
					bind:value={reason}
					maxlength="200"
					class="mt-1 block w-full rounded border-slate-300 text-sm"
				/></label
			>
			{#if revokeError}<p class="text-red-700" role="alert">{revokeError}</p>{/if}
			<div class="flex gap-2">
				<button
					disabled={busy}
					class="rounded bg-red-700 px-4 py-2.5 text-white hover:bg-red-800 disabled:opacity-50 md:py-2"
					>{busy ? m.wireguard.revoking : m.wireguard.revoke}</button
				>
				<button type="button" onclick={() => (revoking = null)} class={cancel}
					>{m.common.cancel}</button
				>
			</div>
		</form>
	</Modal>
{/if}

{#if clientOpen}
	<Modal title={m.wireguard.addClient} onclose={() => (clientOpen = false)}>
		<form onsubmit={addClient} class="max-w-md space-y-4">
			<label class="block"
				>{m.wireguard.name}<input
					bind:value={clientName}
					required
					maxlength="64"
					placeholder="laptop-alice"
					class="mt-1 block w-full rounded border-slate-300 text-sm"
				/></label
			>
			{#if admin}
				<fieldset class="space-y-1">
					<legend>{m.wireguard.owner}</legend>
					<label class="flex items-center gap-2"
						><input type="radio" bind:group={owner} value="me" />{m.wireguard.ownerMe}</label
					>
					<label class="flex items-center gap-2"
						><input type="radio" bind:group={owner} value="server" />{m.wireguard
							.ownerServer}</label
					>
				</fieldset>
			{/if}
			<label class="block"
				><span class="flex items-center gap-2"
					><input type="checkbox" bind:checked={clientPsk} class="rounded border-slate-300" />{m
						.wireguard.usePsk}</span
				><span class="mt-1 block text-xs text-slate-500">{m.wireguard.usePskHint}</span></label
			>
			{#if clientError}<p class="text-red-700" role="alert">{clientError}</p>{/if}
			<div class="flex gap-2">
				<button disabled={busy} class="{button} disabled:opacity-50"
					>{busy ? m.wireguard.adding : m.wireguard.add}</button
				>
				<button type="button" onclick={() => (clientOpen = false)} class={cancel}
					>{m.common.cancel}</button
				>
			</div>
		</form>
	</Modal>
{/if}

{#if deviceOpen}
	<WgAddDevice
		network={id}
		onclose={() => (deviceOpen = false)}
		ondone={(answer) => {
			deviceOpen = false;
			showSecret(answer);
			load();
		}}
	/>
{/if}

{#if secret}
	<WgSecret {secret} onclose={() => (secret = null)} />
{/if}
