<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ApiError, getToken, setToken } from '$lib/api';
	import { m } from '$lib/messages';

	let { error, onretry }: { error: unknown; onretry: () => void } = $props();
	let token = $state(getToken());

	const message = $derived.by(() => {
		if (error instanceof ApiError) {
			if (error.status === 0) return m.errors.network;
			if (error.status === 401) return m.errors.unauthorized;
			if (error.status === 404) return m.errors.notFound;
			return error.message;
		}
		return String(error);
	});
	const needsToken = $derived(error instanceof ApiError && error.status === 401);
	let showToken = $state(false);
	const login = () => goto(`/login?next=${encodeURIComponent(page.url.pathname)}`);
</script>

<div class="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">
	<p class="break-words">{message}</p>
	{#if needsToken}
		<div class="mt-3 flex flex-wrap items-center gap-3">
			<button
				type="button"
				onclick={login}
				class="rounded bg-teal-700 px-3 py-1.5 text-white hover:bg-teal-800">{m.login.title}</button
			>
			<button
				type="button"
				class="text-teal-800 hover:underline"
				onclick={() => (showToken = !showToken)}>{m.token.instead}</button
			>
		</div>
	{/if}
	{#if needsToken && showToken}
		<form
			class="mt-3 flex flex-wrap gap-2"
			onsubmit={(e) => {
				e.preventDefault();
				setToken(token);
				onretry();
			}}
		>
			<label class="sr-only" for="token">{m.token.label}</label>
			<input
				id="token"
				type="password"
				bind:value={token}
				placeholder={m.token.label}
				class="min-w-0 rounded border-slate-300 text-sm"
			/>
			<button class="rounded bg-teal-700 px-3 py-1.5 text-white hover:bg-teal-800"
				>{m.token.save}</button
			>
		</form>
	{/if}
</div>
