<script lang="ts">
	import './layout.css';
	import { afterNavigate, goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api, ApiError, scopeText, setToken } from '$lib/api';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';

	let { children } = $props();
	let activeAlarms = $state(0);
	const me = $derived(session.me);
	// Admin with required 2FA not set up yet -> server answers only the setup -> page shows only that.
	const enrolling = $derived(!!me?.totp_required && !me?.totp_enabled);

	// Logged-in caller. No session or token -> login page.
	$effect(() => {
		if (page.url.pathname === '/login') return;
		api
			.me()
			.then((who) => {
				session.me = who;
				if (who.totp_required && !who.totp_enabled && page.url.pathname !== '/account') {
					goto('/account');
				}
			})
			.catch((e) => {
				if (e instanceof ApiError && e.status === 401) {
					goto(`/login?next=${encodeURIComponent(page.url.pathname)}`);
				}
			});
	});

	// Phone menu: opens under the bar, closes on every navigation.
	let menuOpen = $state(false);
	afterNavigate(() => (menuOpen = false));
	const mobileNav = $derived(
		[
			{ href: '/overview', label: m.nav.overview },
			{ href: '/', label: m.nav.devices },
			{ href: '/jobs', label: m.nav.jobs },
			{ href: '/presets', label: m.nav.presets },
			{ href: '/alarms', label: m.nav.alarms },
			{ href: '/wireguard', label: m.nav.wireguard, hide: !me || me.role === 'viewer' },
			{ href: '/files', label: m.nav.files },
			{ href: '/audit', label: m.nav.audit }
		].filter((l) => !l.hide)
	);
	function current(href: string): boolean {
		const path = page.url.pathname;
		if (href === '/') return path === '/' || path.startsWith('/devices/');
		return path === href || path.startsWith(href + '/');
	}

	async function logout() {
		try {
			await api.logout();
		} finally {
			setToken('');
			session.me = null;
			await goto('/login');
		}
	}

	$effect(() => {
		if (enrolling) return;
		const poll = () =>
			api
				.alarms('active')
				.then((r) => (activeAlarms = Object.values(r.active).reduce((a, b) => a + b, 0)))
				.catch(() => {});
		poll();
		const timer = setInterval(poll, 30000);
		return () => clearInterval(timer);
	});
</script>

<svelte:head>
	<title>{m.appName}</title>
	<link rel="icon" href="/favicon.svg" />
</svelte:head>

<svelte:window
	onkeydown={(e) => {
		if (e.key === 'Escape') menuOpen = false;
	}}
/>

<div class="min-h-screen bg-slate-50 text-slate-900">
	<header class="border-b border-slate-200 bg-white">
		<!-- Phones: 1 bar + menu button; links open in a panel under it. -->
		<div class="flex items-center gap-3 px-3 py-2 md:hidden">
			<a href="/" class="flex items-center gap-2 font-semibold text-teal-800">
				<img src="/favicon.svg" alt="" class="h-6 w-6" />
				{m.appName}
			</a>
			<div class="ml-auto flex items-center gap-2">
				{#if activeAlarms > 0 && !enrolling}<a
						href="/alarms"
						aria-label={m.nav.alarms}
						class="rounded-full bg-red-600 px-2 py-0.5 text-xs text-white">{activeAlarms}</a
					>{/if}
				<button
					type="button"
					onclick={() => (menuOpen = !menuOpen)}
					aria-label={m.nav.menu}
					aria-expanded={menuOpen}
					aria-controls="mobile-menu"
					class="flex h-10 w-10 items-center justify-center rounded text-slate-600 hover:bg-slate-100"
				>
					<svg
						viewBox="0 0 24 24"
						class="h-6 w-6"
						fill="none"
						stroke="currentColor"
						stroke-width="2"><path stroke-linecap="round" d="M4 6h16M4 12h16M4 18h16" /></svg
					>
				</button>
			</div>
		</div>
		{#if menuOpen}
			<div id="mobile-menu" class="border-t border-slate-200 bg-white text-sm md:hidden">
				{#if !enrolling}
					<nav>
						{#each mobileNav as l (l.href)}
							<a
								href={l.href}
								aria-current={current(l.href) ? 'page' : undefined}
								class="block px-4 py-3 {current(l.href)
									? 'bg-teal-50 font-medium text-teal-800'
									: 'text-slate-700 hover:bg-slate-50'}">{l.label}</a
							>
						{/each}
					</nav>
				{/if}
				{#if me && me.via !== 'open'}
					<div class="border-t border-slate-200 py-1 text-slate-600">
						{#if me.role === 'admin' && !enrolling}<a
								href="/settings"
								class="block px-4 py-3 {current('/settings')
									? 'bg-teal-50 font-medium text-teal-800'
									: 'text-slate-700 hover:bg-slate-50'}">{m.login.settings}</a
							>{/if}
						{#if me.via === 'session'}<a
								href="/account"
								class="block px-4 py-3 {current('/account')
									? 'bg-teal-50 font-medium text-teal-800'
									: 'text-slate-700 hover:bg-slate-50'}">{m.login.account}</a
							>{/if}
						<div class="flex flex-wrap items-center gap-2 px-4 py-3">
							<span class="break-all">{me.name} · {m.settings.roles[me.role] ?? me.role}</span>
							{#if me.scope}<span
									class="rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-900"
									title={m.settings.scopeBadgeHelp}
									>{m.settings.scopeBadge(scopeText(me.scope))}</span
								>{/if}
						</div>
						<button
							onclick={logout}
							class="block w-full px-4 py-3 text-left text-teal-800 hover:bg-slate-50"
							>{m.login.logout}</button
						>
					</div>
				{:else if me?.role === 'admin'}
					<div class="border-t border-slate-200">
						<a href="/settings" class="block px-4 py-3 text-slate-700 hover:bg-slate-50"
							>{m.login.settings}</a
						>
					</div>
				{/if}
			</div>
		{/if}
		<div class="mx-auto hidden max-w-7xl items-center gap-6 px-4 py-3 md:flex">
			<a href="/" class="flex items-center gap-2 font-semibold text-teal-800">
				<img src="/favicon.svg" alt="" class="h-6 w-6" />
				{m.appName}
			</a>
			<nav class="text-sm {enrolling ? 'hidden' : ''}">
				<a href="/overview" class="text-slate-600 hover:text-slate-900">{m.nav.overview}</a>
				<a href="/" class="ml-4 text-slate-600 hover:text-slate-900">{m.nav.devices}</a>
				<a href="/jobs" class="ml-4 text-slate-600 hover:text-slate-900">{m.nav.jobs}</a>
				<a href="/presets" class="ml-4 text-slate-600 hover:text-slate-900">{m.nav.presets}</a>
				<a href="/alarms" class="ml-4 text-slate-600 hover:text-slate-900"
					>{m.nav.alarms}{#if activeAlarms > 0}<span
							class="ml-1 rounded-full bg-red-600 px-1.5 py-0.5 text-xs text-white"
							>{activeAlarms}</span
						>{/if}</a
				>
				{#if me && me.role !== 'viewer'}<a
						href="/wireguard"
						class="ml-4 text-slate-600 hover:text-slate-900">{m.nav.wireguard}</a
					>{/if}
				<a href="/files" class="ml-4 text-slate-600 hover:text-slate-900">{m.nav.files}</a>
				<a href="/audit" class="ml-4 text-slate-600 hover:text-slate-900">{m.nav.audit}</a>
			</nav>
			{#if me && me.via !== 'open'}
				<div class="ml-auto flex items-center gap-3 text-sm text-slate-600">
					{#if me.role === 'admin' && !enrolling}<a href="/settings" class="hover:text-slate-900"
							>{m.login.settings}</a
						>{/if}
					{#if me.via === 'session'}<a href="/account" class="hover:text-slate-900"
							>{m.login.account}</a
						>{/if}
					<span>{me.name} · {m.settings.roles[me.role] ?? me.role}</span>
					{#if me.scope}<span
							class="rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-900"
							title={m.settings.scopeBadgeHelp}>{m.settings.scopeBadge(scopeText(me.scope))}</span
						>{/if}
					<button onclick={logout} class="text-teal-800 hover:underline">{m.login.logout}</button>
				</div>
			{:else if me?.role === 'admin'}
				<a href="/settings" class="ml-auto text-sm text-slate-600 hover:text-slate-900"
					>{m.login.settings}</a
				>
			{/if}
		</div>
	</header>
	<main class="mx-auto max-w-7xl px-3 py-4 md:px-4 md:py-6">
		{@render children()}
	</main>
</div>
