<script lang="ts">
	import {
		api,
		ago,
		bytes,
		type WgDeviceMember,
		type WgDeviceSide,
		type WgNetwork,
		type WgSecretAnswer
	} from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import WgHistory from '$lib/components/WgHistory.svelte';
	import WgSecret from '$lib/components/WgSecret.svelte';
	import { m } from '$lib/messages';
	import {
		WG_THRESHOLDS,
		deviceStateColor,
		errorText,
		handshakeDot,
		shortKey,
		stateDot,
		tunnelState,
		type WgState
	} from '$lib/wireguard';

	let { deviceId }: { deviceId: string } = $props();

	let items = $state<WgDeviceMember[] | null>(null);
	// Last contact per network hub. Silent hub -> nothing known about tunnel.
	let hubSeen = $state<Record<string, string | null>>({});
	let error = $state<unknown>(null);
	let notice = $state('');
	let info = $state('');
	// Members with history open (default closed).
	let historyOpen = $state<Record<string, boolean>>({});

	async function load() {
		try {
			const [list, nets, hubs] = await Promise.all([
				api.deviceWireguard(deviceId),
				api.wgNetworks(),
				api.wgHubs()
			]);
			const seen = new Map(hubs.map((h) => [h.id, h.last_seen_at]));
			hubSeen = Object.fromEntries(nets.map((n) => [n.id, seen.get(n.hub.id) ?? null]));
			items = list;
			error = null;
		} catch (e) {
			error = e;
		}
	}

	/** Member state as seen by its hub. */
	const hubState = (mb: WgDeviceMember): WgState =>
		tunnelState(mb.hub_status?.latest_handshake, hubSeen[mb.network_id]);

	const sinceSecs = (iso: string) => Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
	const span = (secs: number) => (secs < 120 ? `${secs} s` : `${Math.round(secs / 60)} min`);

	/** Device report as short phrases. */
	function sideParts(d: WgDeviceSide): string[] {
		const parts: string[] = [];
		if (d.tunnel_status) parts.push(m.wireguard.tunnelStatus(d.tunnel_status));
		if (d.interface_status) parts.push(m.wireguard.interfaceStatus(d.interface_status));
		if (d.last_handshake_secs !== null)
			parts.push(
				d.last_handshake_secs === 0
					? m.wireguard.handshakeNever
					: m.wireguard.handshakeBefore(
							span(d.last_handshake_secs),
							new Date(d.read_at).toLocaleString()
						)
			);
		if (d.bytes_sent !== null || d.bytes_received !== null)
			parts.push(
				m.wireguard.sentReceived(
					d.bytes_sent === null ? '—' : bytes(d.bytes_sent),
					d.bytes_received === null ? '—' : bytes(d.bytes_received)
				)
			);
		return parts;
	}

	/**
	 * Hub connected but device handshake (aged since read) > stale threshold (0 = never);
	 * or device handshake recent but hub stale or never. Silent hub -> tells nothing.
	 */
	function disagree(mb: WgDeviceMember): boolean {
		const d = mb.device_side;
		if (!d || d.last_handshake_secs === null) return false;
		const deviceAge =
			d.last_handshake_secs === 0 ? Infinity : d.last_handshake_secs + sinceSecs(d.read_at);
		const hub = hubState(mb);
		return (
			(hub === 'connected' && deviceAge > WG_THRESHOLDS.stale_secs) ||
			((hub === 'stale' || hub === 'never') && deviceAge < WG_THRESHOLDS.connected_secs)
		);
	}

	/** Queue read of `Device.WireGuard.` on the record that owns the rows. */
	async function readDevice(owner: string) {
		notice = info = '';
		try {
			await api.createTask(owner, {
				kind: 'get_parameter_values',
				payload: { names: ['Device.WireGuard.'] }
			});
			info = m.wireguard.readQueued;
			setTimeout(load, 5000);
		} catch (e) {
			notice = errorText(e);
		}
	}

	// Mounted only while tab open -> no polling otherwise.
	$effect(() => {
		void deviceId;
		load();
		const timer = setInterval(load, 30000);
		return () => clearInterval(timer);
	});

	async function rotateKey(mb: WgDeviceMember) {
		if (!confirm(m.wireguard.confirmRotateKey)) return;
		notice = '';
		try {
			await api.rotateWgMemberKey(mb.id);
			await load();
		} catch (e) {
			notice = errorText(e);
		}
	}

	// --- revoke
	let revoking = $state<WgDeviceMember | null>(null);
	let reason = $state('');
	let revokeError = $state('');
	let busy = $state(false);

	function openRevoke(mb: WgDeviceMember) {
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

	// --- add to a network
	let adding = $state(false);
	let networks = $state<WgNetwork[] | null>(null);
	let network = $state('');
	let keyMode = $state<'device' | 'server'>('device');
	let usePsk = $state(false);
	let addError = $state('');
	// Answer of an add with PSK: shown in one modal, dropped on close.
	let secret = $state<WgSecretAnswer | null>(null);

	// Networks without this device (or its twin).
	const free = $derived(
		(networks ?? []).filter((n) => !(items ?? []).some((i) => i.network_id === n.id))
	);

	async function openAdd() {
		adding = true;
		networks = null;
		network = addError = '';
		keyMode = 'device';
		usePsk = false;
		try {
			networks = await api.wgNetworks();
			network = free[0]?.id ?? '';
		} catch (e) {
			addError = errorText(e);
		}
	}

	async function add(e: SubmitEvent) {
		e.preventDefault();
		if (!network) return;
		busy = true;
		addError = '';
		try {
			const answer = await api.createWgMember(network, {
				kind: 'device',
				device_id: deviceId,
				key_mode: keyMode,
				...(usePsk ? { preshared_key_enabled: true } : {})
			});
			adding = false;
			if (answer.preshared_key) secret = answer;
			await load();
		} catch (err) {
			addError = errorText(err);
		} finally {
			busy = false;
		}
	}

	const button = 'rounded bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-800';
	const cancel = 'rounded border border-slate-300 bg-white px-4 py-2 hover:bg-slate-50';
	const link = 'text-teal-800 hover:underline';
</script>

<div class="mt-3 flex gap-2">
	<button onclick={openAdd} class={button}>{m.wireguard.addToNetwork}</button>
</div>

{#if notice}<p class="mt-3 rounded bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
		{notice}
	</p>{/if}
{#if info}<p class="mt-3 rounded bg-teal-50 px-3 py-2 text-sm text-teal-900" role="status">
		{info}
	</p>{/if}

{#if error}
	<div class="mt-3"><ErrorBox {error} onretry={load} /></div>
{:else if !items}
	<p class="mt-3 text-slate-500">{m.common.loading}</p>
{:else if items.length === 0}
	<p class="mt-3 text-slate-500">{m.wireguard.deviceEmpty}</p>
{:else}
	<div class="mt-3 space-y-3">
		{#each items as mb (mb.id)}
			{@const hs = mb.hub_status}
			{@const ds = mb.device_status}
			{@const side = mb.device_side}
			{@const silent = hubState(mb) === 'unknown'}
			<section class="rounded-md border border-slate-200 bg-white p-4 text-sm">
				<div class="flex flex-wrap items-start justify-between gap-4">
					<div class="min-w-0">
						<a href="/wireguard/networks/{mb.network_id}" class="{link} font-medium"
							>{mb.network_name}</a
						>
						<span class="ml-2 font-mono">{mb.address}</span>
						{#if mb.preshared_key_enabled}<span
								class="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700"
								title={m.wireguard.pskBadgeTitle}>{m.wireguard.pskBadge}</span
							>{/if}
						{#if mb.via_twin}<div class="mt-1 text-xs text-slate-600">
								<a href="/devices/{mb.via_twin.device_id}" class={link}
									>{m.wireguard.viaTwin(mb.via_twin.protocol)}</a
								>
							</div>{/if}
					</div>
					{#if !mb.via_twin}
						<div class="whitespace-nowrap">
							<button onclick={() => rotateKey(mb)} class={link}>{m.wireguard.rotateKey}</button>
							<button onclick={() => openRevoke(mb)} class="ml-3 text-red-700 hover:underline"
								>{m.wireguard.revoke}</button
							>
						</div>
					{/if}
				</div>
				<dl class="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-3">
					<div>
						<dt class="text-slate-500">{m.wireguard.device}</dt>
						<dd>
							{#if ds}
								<span
									class="rounded px-2 py-0.5 text-xs {deviceStateColor[ds.state] ?? 'bg-slate-100'}"
									title={ds.detail ?? ''}>{m.wireguard.states[ds.state] ?? ds.state}</span
								>
								{#if ds.detail}<div class="mt-1 max-w-xs text-xs break-words text-slate-600">
										{ds.detail}
									</div>{/if}
								{#if ds.checked_at}<div class="text-xs text-slate-500" title={ds.checked_at}>
										{m.wireguard.checked(ago(ds.checked_at))}
									</div>{/if}
							{:else}
								<span class="text-slate-400">{m.common.none}</span>
							{/if}
						</dd>
					</div>
					<div>
						<dt class="text-slate-500">{m.wireguard.tunnel}</dt>
						<dd>
							<span class="inline-flex items-center gap-1.5" title={hs?.latest_handshake ?? ''}
								><span
									class="h-2 w-2 rounded-full {silent
										? stateDot.unknown
										: handshakeDot(hs?.latest_handshake)}"
								></span>{hs?.latest_handshake
									? m.wireguard.lastHandshake(ago(hs.latest_handshake))
									: m.wireguard.never}</span
							>
							{#if silent}<div class="text-xs text-slate-500" title={m.wireguard.hubSilentTitle}>
									{m.wireguard.hubSilent}
								</div>{/if}
							{#if hs}
								{#if hs.endpoint}<div
										class="font-mono text-xs break-all text-slate-500 md:break-normal"
									>
										{hs.endpoint}
									</div>{/if}
								<div class="text-xs text-slate-500">
									↓ {bytes(hs.rx_bytes)} ↑ {bytes(hs.tx_bytes)}
								</div>
							{/if}
						</dd>
					</div>
					<div>
						<dt class="text-slate-500">{m.wireguard.publicKey}</dt>
						<dd>
							{#if mb.public_key}<span class="font-mono" title={mb.public_key}
									>{shortKey(mb.public_key)}</span
								>{:else}<span class="text-slate-400">{m.wireguard.noKeyYet}</span>{/if}
							{#if mb.key_mode}<span class="ml-2 text-xs text-slate-500"
									>{m.wireguard.keyModeShort[mb.key_mode] ?? mb.key_mode}</span
								>{/if}
							{#if mb.rotate_requested_at}<div
									class="text-xs text-slate-500"
									title={mb.rotate_requested_at}
								>
									{m.wireguard.rotateRequested(ago(mb.rotate_requested_at))}
								</div>{/if}
						</dd>
					</div>
				</dl>
				<div class="mt-3 border-t border-slate-100 pt-2 text-xs text-slate-600">
					<div class="flex flex-wrap items-baseline justify-between gap-2">
						<div>
							<span class="text-slate-500"
								>{mb.via_twin
									? m.wireguard.deviceReportsVia(mb.via_twin.protocol)
									: m.wireguard.deviceReports}:</span
							>
							{#if side}
								{sideParts(side).join(' · ')}
								<span class="text-slate-500" title={side.read_at}
									>({m.wireguard.asRead(ago(side.read_at))})</span
								>
							{:else}
								<span class="text-slate-400">{m.wireguard.deviceNotRead}</span>
							{/if}
						</div>
						<button onclick={() => readDevice(mb.via_twin?.device_id ?? deviceId)} class={link}
							>{m.wireguard.readFromDevice}</button
						>
					</div>
					{#if disagree(mb)}<p class="mt-1 rounded bg-amber-50 px-2 py-1 text-amber-900">
							{m.wireguard.disagree}
						</p>{/if}
				</div>
				{#if mb.device_id}
					<div class="mt-3 border-t border-slate-100 pt-2 text-xs">
						<button
							onclick={() => (historyOpen[mb.id] = !historyOpen[mb.id])}
							class={link}
							aria-expanded={!!historyOpen[mb.id]}
							>{historyOpen[mb.id] ? m.wireguard.hideHistory : m.wireguard.history}</button
						>
						{#if historyOpen[mb.id]}
							<WgHistory deviceId={mb.device_id} networkId={mb.network_id} />
						{/if}
					</div>
				{/if}
			</section>
		{/each}
	</div>
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
			<div class="flex flex-wrap gap-2">
				<button
					disabled={busy}
					class="rounded bg-red-700 px-4 py-2 text-white hover:bg-red-800 disabled:opacity-50"
					>{busy ? m.wireguard.revoking : m.wireguard.revoke}</button
				>
				<button type="button" onclick={() => (revoking = null)} class={cancel}
					>{m.common.cancel}</button
				>
			</div>
		</form>
	</Modal>
{/if}

{#if adding}
	<Modal title={m.wireguard.addToNetwork} onclose={() => (adding = false)}>
		<form onsubmit={add} class="max-w-md space-y-4">
			{#if !networks}
				{#if !addError}<p class="text-slate-500">{m.common.loading}</p>{/if}
			{:else if free.length === 0}
				<p class="text-slate-600">{m.wireguard.noNetworkLeft}</p>
			{:else}
				<label class="block"
					>{m.wireguard.network}<select
						bind:value={network}
						required
						class="mt-1 block w-full rounded border-slate-300 text-sm"
					>
						{#each free as n (n.id)}
							<option value={n.id}>{n.name} ({n.ipv4_prefix})</option>
						{/each}
					</select></label
				>
				<fieldset class="space-y-1">
					<legend>{m.wireguard.keyMode}</legend>
					{#each ['device', 'server'] as const as mode (mode)}
						<label class="flex items-center gap-2"
							><input type="radio" bind:group={keyMode} value={mode} />{m.wireguard.keyModes[
								mode
							]}</label
						>
					{/each}
				</fieldset>
				<label class="block"
					><span class="flex items-center gap-2"
						><input type="checkbox" bind:checked={usePsk} class="rounded border-slate-300" />{m
							.wireguard.usePsk}</span
					><span class="mt-1 block text-xs text-slate-500">{m.wireguard.usePskHint}</span></label
				>
			{/if}
			{#if addError}<p class="text-red-700" role="alert">{addError}</p>{/if}
			<div class="flex flex-wrap gap-2">
				{#if networks && free.length > 0}
					<button disabled={busy || !network} class="{button} disabled:opacity-50"
						>{busy ? m.wireguard.adding : m.wireguard.add}</button
					>
				{/if}
				<button type="button" onclick={() => (adding = false)} class={cancel}
					>{m.common.cancel}</button
				>
			</div>
		</form>
	</Modal>
{/if}

{#if secret}
	<WgSecret {secret} onclose={() => (secret = null)} />
{/if}
