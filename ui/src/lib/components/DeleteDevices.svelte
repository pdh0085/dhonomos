<script lang="ts">
	import { api, type DeleteResult, type Device } from '$lib/api';
	import { MAX_DELETE } from '$lib/devicelist';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';

	let {
		devices,
		ondone,
		oncancel
	}: {
		/** Devices selected in the list. */
		devices: Device[];
		ondone: (result: DeleteResult) => void;
		oncancel: () => void;
	} = $props();

	// Names shown before "and N more".
	const SHOWN = 20;

	let typed = $state('');
	let busy = $state(false);
	let error = $state<unknown>(null);

	const count = $derived(devices.length);
	// Retired -> deleted as is; others -> retired first.
	const toRetire = $derived(devices.filter((d) => d.status !== 'retired').length);
	const confirmed = $derived(typed.trim() === String(count));
	const tooMany = $derived(count > MAX_DELETE);
	const name = (d: Device) => d.serial_number ?? d.endpoint_id ?? d.id;

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!confirmed || tooMany || busy) return;
		busy = true;
		error = null;
		try {
			ondone(
				await api.deleteDevices(
					devices.map((d) => d.id),
					true
				)
			);
		} catch (err) {
			error = err;
		} finally {
			busy = false;
		}
	}
</script>

<Modal title={m.devices.remove.title} onclose={oncancel}>
	<form onsubmit={submit} class="space-y-4">
		<p class="font-medium">{m.devices.remove.intro(count)}</p>
		<ul class="max-h-48 list-disc space-y-0.5 overflow-y-auto pl-6 font-mono text-xs">
			{#each devices.slice(0, SHOWN) as d (d.id)}
				<li class="break-all">
					{name(d)} <span class="font-sans text-slate-500">{d.status}</span>
				</li>
			{/each}
		</ul>
		{#if count > SHOWN}<p class="text-slate-600">{m.devices.remove.more(count - SHOWN)}</p>{/if}

		<ul
			class="list-disc space-y-1 rounded border border-red-200 bg-red-50 py-2 pr-3 pl-7 text-red-900"
		>
			<li>{m.devices.remove.dataGone}</li>
			<li>{m.devices.remove.revoked}</li>
			{#if toRetire > 0}<li>{m.devices.remove.retireFirst(toRetire)}</li>{/if}
			<li>{m.devices.remove.reregister}</li>
		</ul>

		<label class="block"
			><span>{m.devices.remove.confirm(count)}</span><input
				bind:value={typed}
				inputmode="numeric"
				autocomplete="off"
				spellcheck="false"
				class="mt-1 block w-40 rounded border-slate-300 text-sm"
			/></label
		>
		{#if tooMany}
			<p class="text-xs text-slate-700">{m.devices.remove.tooMany(MAX_DELETE)}</p>
		{:else if !confirmed}
			<p class="text-xs text-slate-700">{m.devices.remove.mismatch(count)}</p>
		{/if}
		{#if error}<ErrorBox {error} onretry={() => (error = null)} />{/if}
		<div class="flex flex-wrap gap-2">
			<button
				disabled={busy || !confirmed || tooMany}
				class="rounded bg-red-700 px-4 py-2 text-white hover:bg-red-800 disabled:opacity-50"
				>{busy ? m.devices.remove.working : m.devices.remove.submit}</button
			>
			<button
				type="button"
				onclick={oncancel}
				class="rounded border border-slate-300 bg-white px-4 py-2 hover:bg-slate-50"
				>{m.common.cancel}</button
			>
		</div>
	</form>
</Modal>
