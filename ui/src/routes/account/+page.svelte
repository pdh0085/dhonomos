<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, type Me, type TotpSetup } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';

	let me = $state<Me | null>(null);
	let error = $state<unknown>(null);
	let notice = $state('');
	// Secret in setup + its confirm code.
	let setup = $state<TotpSetup | null>(null);
	let confirmCode = $state('');
	// Current code -> new device or new recovery codes.
	let currentCode = $state('');
	let asking = $state<'device' | 'codes' | 'disable' | null>(null);
	let password = $state('');
	// Recovery codes, shown once.
	let recoveryCodes = $state<string[] | null>(null);
	let copied = $state(false);
	// Shown codes = codes of the enrollment that held up an admin.
	let afterEnroll = $state(false);

	const enabled = $derived(!!me?.totp_enabled);
	const mustEnroll = $derived(!!me?.totp_required && !enabled);
	// Server requires it -> admin cannot turn it off.
	const canTurnOff = $derived(enabled && !me?.totp_required);

	async function load() {
		error = null;
		try {
			me = await api.me();
			session.me = me;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});

	/** Run `f`; failure -> notice. */
	async function act(f: () => Promise<void>) {
		notice = '';
		try {
			await f();
		} catch (e) {
			notice = e instanceof Error ? e.message : String(e);
		}
	}

	const startSetup = (code?: string) =>
		act(async () => {
			setup = await api.totpSetup(code);
			confirmCode = currentCode = '';
			asking = null;
		});

	const confirm = (e: SubmitEvent) => {
		e.preventDefault();
		return act(async () => {
			const first = mustEnroll;
			recoveryCodes = (await api.totpEnable(confirmCode.trim())).recovery_codes;
			afterEnroll = first;
			setup = null;
			confirmCode = '';
			copied = false;
			await load();
		});
	};

	const newCodes = (e: SubmitEvent) => {
		e.preventDefault();
		return act(async () => {
			recoveryCodes = (await api.totpRecoveryCodes(currentCode.trim())).recovery_codes;
			currentCode = '';
			asking = null;
			copied = false;
		});
	};

	const turnOff = (e: SubmitEvent) => {
		e.preventDefault();
		return act(async () => {
			await api.totpDisable(password, currentCode.trim());
			password = currentCode = '';
			asking = null;
			notice = m.account.turnedOff;
			await load();
		});
	};

	const newDevice = (e: SubmitEvent) => {
		e.preventDefault();
		return startSetup(currentCode.trim());
	};

	function ask(what: 'device' | 'codes' | 'disable') {
		asking = asking === what ? null : what;
		currentCode = password = '';
		notice = '';
	}

	/** Server QR code as image; SVG never inserted as markup. */
	function qrSource(svg: string): string {
		try {
			return `data:image/svg+xml;base64,${btoa(svg)}`;
		} catch {
			return '';
		}
	}

	/** Key in groups of 4 -> easy to read + type. */
	const grouped = (key: string) => key.replace(/(.{4})(?=.)/g, '$1 ');

	async function copy() {
		try {
			await navigator.clipboard.writeText((recoveryCodes ?? []).join('\n'));
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			// No clipboard access -> codes on screen, copy by hand.
		}
	}

	function download() {
		const text = [
			m.account.downloadHeader(me?.name ?? ''),
			m.account.downloadNote,
			'',
			...(recoveryCodes ?? []),
			''
		].join('\n');
		const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
		const a = document.createElement('a');
		a.href = url;
		a.download = 'dhonomos-recovery-codes.txt';
		a.click();
		URL.revokeObjectURL(url);
	}

	async function done() {
		recoveryCodes = null;
		// Admin forced to enroll -> can use Dhonomos now.
		if (afterEnroll) await goto('/');
	}

	const input = 'rounded border-slate-300 text-sm';
	const button = 'rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2';
	const link = 'py-2 text-sm text-teal-800 hover:underline md:py-0';
</script>

{#if error}
	<ErrorBox {error} onretry={load} />
{:else if me}
	<h1 class="text-xl font-semibold">{m.account.title}</h1>
	<p class="mt-1 text-sm text-slate-600">{me.name} · {m.settings.roles[me.role] ?? me.role}</p>

	<section class="mt-6 max-w-2xl rounded-md border border-slate-200 bg-white p-4 md:p-5">
		<h2 class="font-semibold">{m.account.twoFactor}</h2>

		{#if mustEnroll}
			<div class="mt-3 rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
				<p class="font-medium">{m.account.enrollTitle}</p>
				<p class="mt-1">{m.account.enrollBody}</p>
			</div>
		{/if}
		{#if notice}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm" role="status">
				{notice}
			</p>{/if}

		{#if recoveryCodes}
			<div class="mt-4">
				<h3 class="text-sm font-semibold">{m.account.recoveryTitle}</h3>
				<p class="mt-1 text-sm text-slate-600">{m.account.recoverySaved}</p>
				<ul class="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 rounded bg-slate-50 p-3 font-mono text-sm">
					{#each recoveryCodes as c (c)}<li>{c}</li>{/each}
				</ul>
				<div class="mt-3 flex flex-wrap gap-4">
					<button onclick={copy} class={link}>{copied ? m.account.copied : m.account.copy}</button>
					<button onclick={download} class={link}>{m.account.download}</button>
				</div>
				<button onclick={done} class="{button} mt-4">{m.account.done}</button>
			</div>
		{:else if !me.totp_available}
			<p class="mt-3 text-sm text-slate-600">
				{me.via === 'session' ? m.account.notAvailable : m.account.notAvailableSession}
			</p>
		{:else if setup}
			<div class="mt-4">
				<p class="text-sm text-slate-600">{m.account.scan}</p>
				<div class="mt-3 flex flex-wrap items-start gap-6">
					{#if qrSource(setup.qr_svg)}
						<img
							src={qrSource(setup.qr_svg)}
							alt={m.account.qrAlt}
							class="h-48 w-48 rounded border border-slate-200"
						/>
					{/if}
					<div class="text-sm">
						<p class="text-slate-600">{m.account.key}</p>
						<p class="mt-1 font-mono break-all select-all">{grouped(setup.secret)}</p>
					</div>
				</div>
				<form onsubmit={confirm} class="mt-4 flex flex-wrap items-end gap-3">
					<label class="text-sm"
						><span class="mb-1 block text-slate-600">{m.account.confirm}</span><input
							bind:value={confirmCode}
							autocomplete="one-time-code"
							inputmode="numeric"
							pattern="[0-9 ]*"
							maxlength="7"
							required
							class="{input} font-mono tracking-widest"
						/></label
					>
					<button class={button}>{m.account.confirmButton}</button>
					<button type="button" onclick={() => (setup = null)} class={link}
						>{m.account.cancel}</button
					>
				</form>
				<p class="mt-2 text-xs text-slate-500">{m.account.codeWait}</p>
			</div>
		{:else if !enabled}
			<p class="mt-3 text-sm text-slate-600">{m.account.intro}</p>
			<p class="mt-3 text-sm">
				<span class="rounded bg-slate-100 px-2 py-0.5 text-xs">{m.account.off}</span>
				{#if me.totp_required}<span class="ml-2 text-xs text-slate-500">{m.account.required}</span
					>{/if}
			</p>
			<button onclick={() => startSetup()} class="{button} mt-4">{m.account.setUp}</button>
		{:else}
			<p class="mt-3 text-sm text-slate-600">{m.account.intro}</p>
			<p class="mt-3 text-sm">
				<span class="rounded bg-teal-100 px-2 py-0.5 text-xs text-teal-900">{m.account.on}</span>
				{#if me.totp_required}<span class="ml-2 text-xs text-slate-500">{m.account.required}</span
					>{/if}
			</p>
			<div class="mt-4 flex flex-wrap gap-5">
				<button onclick={() => ask('device')} class={link}>{m.account.setUpNew}</button>
				<button onclick={() => ask('codes')} class={link}>{m.account.newCodes}</button>
				{#if canTurnOff}
					<button
						onclick={() => ask('disable')}
						class="py-2 text-sm text-red-700 hover:underline md:py-0"
						>{m.account.disableTitle}</button
					>
				{/if}
			</div>
			{#if me.totp_required}
				<p class="mt-2 text-xs text-slate-500">{m.account.disableAdmin}</p>
			{/if}
			{#if asking}
				<form
					onsubmit={asking === 'device' ? newDevice : asking === 'codes' ? newCodes : turnOff}
					class="mt-4 grid max-w-sm gap-3"
				>
					<p class="text-sm text-slate-600">
						{asking === 'device'
							? m.account.currentCode
							: asking === 'codes'
								? m.account.newCodesHelp
								: m.account.disableHelp}
					</p>
					{#if asking === 'disable'}
						<label class="text-sm"
							><span class="mb-1 block text-slate-600">{m.account.password}</span><input
								bind:value={password}
								type="password"
								autocomplete="current-password"
								required
								class="{input} w-full"
							/></label
						>
					{/if}
					<label class="text-sm"
						><span class="mb-1 block text-slate-600">{m.login.code}</span><input
							bind:value={currentCode}
							autocomplete="one-time-code"
							required
							class="{input} w-full font-mono"
						/></label
					>
					<div class="flex gap-3">
						<button
							class={asking === 'disable'
								? 'rounded bg-red-700 px-4 py-2.5 text-sm text-white hover:bg-red-800 md:py-2'
								: button}
							>{asking === 'device'
								? m.account.setUpNew
								: asking === 'codes'
									? m.account.makeCodes
									: m.account.disable}</button
						>
						<button type="button" onclick={() => (asking = null)} class={link}
							>{m.account.cancel}</button
						>
					</div>
					<p class="text-xs text-slate-500">{m.account.codeWait}</p>
				</form>
			{/if}
		{/if}
	</section>
{/if}
