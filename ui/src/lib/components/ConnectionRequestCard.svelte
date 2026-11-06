<script lang="ts">
	import { api, ago, type Device, type Parameter } from '$lib/api';
	import { m } from '$lib/messages';

	let {
		device,
		params,
		onchanged
	}: { device: Device; params: Parameter[]; onchanged: () => void | Promise<void> } = $props();

	const t = m.device.connection;
	const time = (iso: string) => new Date(iso).toLocaleString();

	// What the device says it supports (TR-181, TR-098 roots), if read.
	const advertised = $derived(
		params.find((p) =>
			['Device', 'InternetGatewayDevice'].some(
				(root) => p.path === `${root}.ManagementServer.SupportedConnReqMethods`
			)
		)?.value || null
	);

	let busy = $state(false);
	let result = $state('');

	async function send() {
		busy = true;
		try {
			result = m.device.wakeResult((await api.wake(device.id)).connection_request);
		} catch (err) {
			result = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
		// Card shows what the wake recorded.
		await onchanged();
	}
</script>

<section class="mt-4 rounded-md border border-slate-200 bg-white p-4">
	<div class="flex flex-wrap items-start gap-4">
		<div class="min-w-0">
			<h2 class="text-sm font-medium text-slate-700">{t.title}</h2>
			<p class="text-xs text-slate-500">{t.intro}</p>
		</div>
		<button
			onclick={send}
			disabled={busy}
			class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100 disabled:opacity-50 md:ml-auto"
			>{busy ? t.sending : m.device.wake}</button
		>
	</div>
	<!-- Phones: label above its value. -->
	<dl
		class="mt-3 grid grid-cols-1 gap-x-6 text-sm md:grid-cols-[max-content_1fr] md:gap-y-2 [&>dt]:mt-2 [&>dt:first-child]:mt-0 md:[&>dt]:mt-0"
	>
		<dt class="text-slate-500">{t.http}</dt>
		<dd class="font-mono break-all">{device.connection_request_url || t.httpNone}</dd>

		<dt class="text-slate-500">{t.xmpp}</dt>
		<dd>
			{#if device.xmpp_connected_at}
				<span class="rounded bg-sky-100 px-1.5 py-0.5 text-xs text-sky-800"
					>{m.devices.xmppBadge}</span
				>
				{t.xmppConnected(time(device.xmpp_connected_at), ago(device.xmpp_connected_at))}
				{#if device.xmpp_jid}<div class="font-mono text-xs break-all text-slate-600">
						{t.xmppJid(device.xmpp_jid)}
					</div>{/if}
			{:else}
				<span class="text-slate-600">{t.xmppNotConnected}</span>
			{/if}
		</dd>

		<dt class="text-slate-500">{t.udp}</dt>
		<dd>
			{#if device.udp_cr_address}
				<span class="font-mono break-all md:break-normal">{device.udp_cr_address}</span>
				{#if device.udp_cr_seen_at}
					<span class="text-slate-500" title={time(device.udp_cr_seen_at)}
						>{t.udpKnown(ago(device.udp_cr_seen_at))}</span
					>
				{/if}
			{:else}
				<span class="text-slate-600">{t.udpNone}</span>
			{/if}
		</dd>

		{#if advertised}
			<dt class="text-slate-500">{t.advertised}</dt>
			<dd>
				<span class="font-mono break-all md:break-normal">{advertised}</span>
				<div class="text-xs text-slate-500">{t.advertisedNote}</div>
			</dd>
		{/if}

		<dt class="text-slate-500">{t.lastWake}</dt>
		<dd>
			{#if device.last_wake_at}
				<span title={time(device.last_wake_at)}>{ago(device.last_wake_at)}</span>
				<span class="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700"
					>{device.last_wake_method
						? t.via(t.methods[device.last_wake_method] ?? device.last_wake_method)
						: t.nothingSent}</span
				>
				<span class="break-all">{device.last_wake_outcome ?? ''}</span>
			{:else}
				<span class="text-slate-600">{t.neverWoken}</span>
			{/if}
		</dd>
	</dl>
	{#if result}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm">{result}</p>{/if}
</section>
