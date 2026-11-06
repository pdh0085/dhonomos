<script lang="ts">
	import { saveText, type WgSecretAnswer } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';
	import { qrSource } from '$lib/wireguard';

	// Answer of create / re-key / change: private key + PSK exist only in it.
	// Parent drops it in `onclose`; nothing here keeps or logs it.
	let { secret, onclose }: { secret: WgSecretAnswer; onclose: () => void } = $props();

	const qr = $derived(secret.qr_svg ? qrSource(secret.qr_svg) : '');
	let copied = $state(false);

	function save() {
		if (secret.config) saveText(secret.config, secret.config_filename ?? 'wg.conf');
	}

	async function copyPsk() {
		if (!secret.preshared_key) return;
		try {
			await navigator.clipboard.writeText(secret.preshared_key);
			copied = true;
		} catch {
			// No clipboard access -> key on screen, copy by hand.
		}
	}
</script>

<Modal
	title={secret.config ? m.wireguard.secretTitle(secret.name) : m.wireguard.pskTitle(secret.name)}
	{onclose}
>
	<div class="space-y-4">
		{#if secret.config}
			<p
				class="rounded border border-amber-300 bg-amber-50 p-3 font-medium text-amber-900"
				role="alert"
			>
				{m.wireguard.secretWarning}
			</p>
		{/if}
		{#if secret.preshared_key}
			<p
				class="rounded border border-amber-300 bg-amber-50 p-3 font-medium text-amber-900"
				role="alert"
			>
				{m.wireguard.pskWarning}
			</p>
		{/if}
		<div class="flex flex-wrap items-start gap-6">
			{#if qr}
				<div>
					<img
						src={qr}
						alt={m.wireguard.qrAlt}
						class="h-64 w-64 rounded border border-slate-200 bg-white"
					/>
					<p class="mt-1 text-xs text-slate-500">{m.wireguard.scanHint}</p>
				</div>
			{/if}
			<div class="min-w-0 space-y-3">
				<p>
					<span class="text-slate-600">{m.wireguard.address}:</span>
					<span class="font-mono">{secret.address}</span>
				</p>
				{#if secret.config}
					<button
						type="button"
						onclick={save}
						class="rounded bg-teal-700 px-4 py-2 text-white hover:bg-teal-800"
						>{m.wireguard.download}</button
					>
					<p class="font-mono text-xs break-all text-slate-500">{secret.config_filename}</p>
				{/if}
				{#if secret.preshared_key}
					<div>
						<p class="text-slate-600">{m.wireguard.presharedKey}:</p>
						<div class="mt-1 flex items-center gap-2">
							<code class="min-w-0 rounded bg-slate-100 px-2 py-1 font-mono text-sm break-all"
								>{secret.preshared_key}</code
							>
							<button
								type="button"
								onclick={copyPsk}
								class="rounded border border-slate-300 bg-white px-3 py-1 text-sm hover:bg-slate-50"
								>{copied ? m.wireguard.copied : m.wireguard.copy}</button
							>
						</div>
					</div>
				{/if}
			</div>
		</div>
		<button
			type="button"
			onclick={onclose}
			class="rounded border border-slate-300 bg-white px-4 py-2 hover:bg-slate-50"
			>{m.wireguard.done}</button
		>
	</div>
</Modal>
