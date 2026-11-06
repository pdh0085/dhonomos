<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, ApiError, setToken } from '$lib/api';
	import { safeNext } from '$lib/nav';
	import { m } from '$lib/messages';

	let username = $state('');
	let password = $state('');
	let token = $state('');
	let error = $state('');
	let tokenMode = $state(false);
	let sso = $state(false);
	// 2FA: asked only after the password is right.
	let needsCode = $state(false);
	let code = $state('');
	let recovery = $state(false);
	let codeInput = $state<HTMLInputElement | null>(null);

	$effect(() => {
		if (needsCode) codeInput?.focus();
	});

	// SSO: offered if configured. Failure -> back with ?sso_error=.
	$effect(() => {
		error = new URLSearchParams(location.search).get('sso_error') ?? '';
		api.authConfig().then(
			(c) => (sso = c.sso),
			() => {}
		);
	});

	const next = () => safeNext(new URLSearchParams(location.search).get('next'));

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		try {
			if (tokenMode) {
				setToken(token);
				await api.me();
			} else {
				setToken('');
				await api.login(username, password, needsCode ? code.trim() : undefined);
			}
			// Admin without 2FA -> 2FA setup first.
			const me = await api.me();
			await goto(me.totp_required && !me.totp_enabled ? '/account' : next());
		} catch (err) {
			if (err instanceof ApiError && err.data.totp_required === true) {
				needsCode = true;
				return;
			}
			error = err instanceof Error ? err.message : String(err);
		}
	}

	function startOver() {
		needsCode = false;
		recovery = false;
		code = password = '';
		error = '';
	}

	function toggleRecovery() {
		recovery = !recovery;
		code = '';
		error = '';
	}

	const input = 'w-full rounded border-slate-300 text-sm';
</script>

<div class="mx-auto mt-6 max-w-sm rounded-md border border-slate-200 bg-white p-5 md:mt-16 md:p-6">
	<h1 class="text-lg font-semibold">{m.login.title}</h1>
	{#if sso}
		<a
			href="/api/v1/auth/oidc/login?return_to={encodeURIComponent(next())}"
			class="mt-4 block rounded border border-teal-700 px-4 py-2.5 text-center text-sm text-teal-800 hover:bg-teal-50 md:py-2"
			>{m.login.sso}</a
		>
		<p class="mt-3 text-center text-xs text-slate-500">{m.login.or}</p>
	{/if}
	<form onsubmit={submit} class="mt-4 grid gap-3">
		{#if tokenMode}
			<label class="text-sm">
				<span class="mb-1 block text-slate-600">{m.token.label}</span>
				<input bind:value={token} type="password" required class={input} />
			</label>
		{:else}
			<label class="text-sm">
				<span class="mb-1 block text-slate-600">{m.login.username}</span>
				<input
					bind:value={username}
					autocomplete="username"
					required
					readonly={needsCode}
					class={input}
				/>
			</label>
			<label class="text-sm">
				<span class="mb-1 block text-slate-600">{m.login.password}</span>
				<input
					bind:value={password}
					type="password"
					autocomplete="current-password"
					required
					readonly={needsCode}
					class={input}
				/>
			</label>
			{#if needsCode}
				<p class="text-sm text-slate-600">{m.login.codeNeeded}</p>
				<label class="text-sm">
					<span class="mb-1 block text-slate-600"
						>{recovery ? m.login.recoveryCode : m.login.code}</span
					>
					{#if recovery}
						<input
							bind:this={codeInput}
							bind:value={code}
							autocomplete="off"
							autocapitalize="characters"
							spellcheck="false"
							required
							class="{input} font-mono"
						/>
						<span class="mt-1 block text-xs text-slate-500">{m.login.recoveryHelp}</span>
					{:else}
						<input
							bind:this={codeInput}
							bind:value={code}
							autocomplete="one-time-code"
							inputmode="numeric"
							pattern="[0-9 ]*"
							maxlength="7"
							required
							class="{input} font-mono tracking-widest"
						/>
						<span class="mt-1 block text-xs text-slate-500">{m.login.codeHelp}</span>
					{/if}
				</label>
			{/if}
		{/if}
		<button class="rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2"
			>{m.login.submit}</button
		>
		{#if error}<p class="text-sm text-red-700">{error}</p>{/if}
	</form>
	{#if needsCode && !tokenMode}
		<button
			onclick={toggleRecovery}
			class="mt-1 block py-2 text-sm text-teal-800 hover:underline md:mt-3 md:py-0 md:text-xs"
			>{recovery ? m.login.useApp : m.login.useRecovery}</button
		>
		<button
			onclick={startOver}
			class="mt-1 block py-2 text-sm text-teal-800 hover:underline md:mt-3 md:py-0 md:text-xs"
			>{m.login.startOver}</button
		>
	{/if}
	<button
		onclick={() => (tokenMode = !tokenMode)}
		class="mt-1 py-2 text-sm text-teal-800 hover:underline md:mt-3 md:py-0 md:text-xs"
		>{m.login.useToken}</button
	>
</div>
