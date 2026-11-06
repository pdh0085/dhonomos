<script lang="ts">
	import type { Snippet } from 'svelte';
	import { m } from '$lib/messages';

	let { title, onclose, children }: { title: string; onclose: () => void; children: Snippet } =
		$props();

	let dialog = $state<HTMLDialogElement | null>(null);

	$effect(() => {
		if (dialog && !dialog.open) dialog.showModal();
	});
</script>

<!-- Modal dialog: page behind unchanged, Escape closes. -->
<dialog
	bind:this={dialog}
	oncancel={(e) => {
		e.preventDefault();
		onclose();
	}}
	class="m-auto w-[calc(100%-1rem)] max-w-3xl rounded-lg border border-slate-200 p-0 shadow-xl backdrop:bg-slate-900/40 md:w-full"
>
	<div class="flex items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 md:px-5">
		<h2 class="min-w-0 text-base font-semibold">{title}</h2>
		<button
			type="button"
			onclick={onclose}
			aria-label={m.common.close}
			title={m.common.close}
			class="rounded px-2 py-1 text-slate-500 hover:bg-slate-100">✕</button
		>
	</div>
	<div class="max-h-[calc(100dvh-5rem)] overflow-y-auto p-4 text-sm md:max-h-[80vh] md:p-5">
		{@render children()}
	</div>
</dialog>
