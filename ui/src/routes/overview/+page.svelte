<script lang="ts">
	import { api, type Overview, type WgSummary } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';
	import { errorText, stateParts, stateText, type WgState } from '$lib/wireguard';

	let o = $state<Overview | null>(null);
	let error = $state<unknown>(null);
	// WireGuard: operators and up. Its failure -> rest of the page unaffected.
	const showWg = $derived(!!session.me && session.me.role !== 'viewer');
	let wg = $state<WgSummary | null>(null);
	let wgError = $state('');

	async function loadWg() {
		try {
			wg = await api.wgSummary();
			wgError = '';
		} catch (e) {
			wgError = errorText(e);
		}
	}

	async function load() {
		if (showWg) loadWg();
		try {
			o = await api.overview();
			error = null;
		} catch (e) {
			error = e;
		}
	}

	// Device lists behind the figures (filter fields `wg_handshake`, `wg_member`).
	const deviceList = (filter: string) => `/?filter=${encodeURIComponent(filter)}`;
	const wgLinks: Partial<Record<WgState, { href: string; title: string }>> = {
		stale: { href: deviceList('wg_handshake > 15m'), title: m.overview.wgStaleLink },
		never: {
			href: deviceList('wg_member = true and not wg_handshake exists'),
			title: m.overview.wgNeverLink
		}
	};
	const wgFigures = $derived<WgState[]>([
		'connected',
		'idle',
		'stale',
		'never',
		...(wg && wg.totals.device.unknown > 0 ? (['unknown'] as const) : [])
	]);

	$effect(() => {
		void showWg;
		load();
		const timer = setInterval(load, 30000);
		return () => clearInterval(timer);
	});

	const pct = (n: number, total: number) => (total ? Math.round((n * 100) / total) : 0);
	const sessions = $derived.by(() => {
		if (!o) return { bars: [], max: 1, total: 0 };
		// 1 bar per minute of the last hour, gaps included.
		const now = Math.floor(Date.now() / 60000);
		const byMinute = new Map(
			o.sessions_per_minute.map((p) => [Math.floor(new Date(p.ts).getTime() / 60000), p.n])
		);
		const bars = Array.from({ length: 60 }, (_, i) => byMinute.get(now - 59 + i) ?? 0);
		return { bars, max: Math.max(1, ...bars), total: bars.reduce((a, b) => a + b, 0) };
	});
	const card = 'rounded-md border border-slate-200 bg-white p-4';
	const severityColor: Record<string, string> = {
		critical: 'text-red-700',
		major: 'text-red-600',
		minor: 'text-amber-700',
		warning: 'text-sky-700'
	};
</script>

<h1 class="text-xl font-semibold">{m.overview.title}</h1>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !o}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else}
	<div class="mt-4 grid gap-4 md:grid-cols-4">
		<div class={card}>
			<div class="text-sm text-slate-500">{m.overview.active}</div>
			<div class="mt-1 text-3xl font-semibold tabular-nums">{o.active.toLocaleString()}</div>
			<div class="mt-1 text-xs text-slate-500">
				{Object.entries(o.by_protocol)
					.map(([p, n]) => `${p.toUpperCase()} ${n.toLocaleString()}`)
					.join(' · ')}
			</div>
		</div>
		<div class="{card} md:col-span-2">
			<div class="text-sm text-slate-500">{m.overview.online}</div>
			<div class="mt-2 grid grid-cols-3 gap-2">
				{#each [['m15', o.online.m15], ['h1', o.online.h1], ['d1', o.online.d1]] as const as [k, n] (k)}
					<div>
						<div class="text-2xl font-semibold tabular-nums">{pct(n, o.active)}%</div>
						<div class="text-xs text-slate-500">{n.toLocaleString()} · {m.overview[k]}</div>
						<div class="mt-1 h-1.5 rounded bg-slate-200">
							<div class="h-1.5 rounded bg-teal-600" style="width: {pct(n, o.active)}%"></div>
						</div>
					</div>
				{/each}
			</div>
		</div>
		<div class={card}>
			<div class="text-sm text-slate-500">{m.overview.alarms}</div>
			{#if Object.keys(o.alarms).length === 0}
				<div class="mt-1 text-3xl font-semibold text-emerald-700">{m.overview.noAlarms}</div>
			{:else}
				<a href="/alarms" class="mt-1 block">
					{#each Object.entries(o.alarms) as [sev, n] (sev)}
						<div class="text-lg {severityColor[sev] ?? ''}">
							<span class="font-semibold tabular-nums">{n}</span>
							{sev}
						</div>
					{/each}
				</a>
			{/if}
		</div>
	</div>

	<div class="mt-4 grid gap-4 md:grid-cols-3">
		<div class="{card} md:col-span-2">
			<div class="flex items-baseline justify-between">
				<div class="text-sm text-slate-500">{m.overview.sessions}</div>
				<div class="text-xs text-slate-500">{m.overview.sessionsTotal(sessions.total)}</div>
			</div>
			<svg viewBox="0 0 600 120" class="mt-2 h-32 w-full" preserveAspectRatio="none" role="img">
				{#each sessions.bars as n, i (i)}
					<rect
						x={i * 10 + 1}
						width="8"
						y={120 - (n * 116) / sessions.max}
						height={(n * 116) / sessions.max}
						class="fill-teal-600"><title>{n}</title></rect
					>
				{/each}
			</svg>
		</div>
		<div class={card}>
			<div class="text-sm text-slate-500">{m.overview.queue}</div>
			<dl class="mt-2 grid grid-cols-2 gap-y-1 text-sm">
				{#each Object.keys(m.overview.tasks) as st (st)}
					<dt class="text-slate-600">{m.overview.tasks[st]}</dt>
					<dd class="text-right tabular-nums">{(o.tasks[st] ?? 0).toLocaleString()}</dd>
				{/each}
			</dl>
			<a href="/jobs" class="mt-3 block text-sm text-teal-800 hover:underline"
				>{m.overview.jobs(o.jobs_running)}</a
			>
		</div>
	</div>

	{#if showWg && (wg || wgError)}
		<div class="{card} mt-4">
			<div class="text-sm text-slate-500">{m.overview.wireguard}</div>
			{#if !wg}
				<p class="mt-2 text-sm text-red-700" role="alert">{wgError}</p>
			{:else if wg.networks.length === 0}
				<p class="mt-2 text-sm text-slate-600">
					{m.overview.wgNoNetworks}
					<a href="/wireguard" class="text-teal-800 hover:underline">{m.overview.wgOpen}</a>
				</p>
			{:else}
				<div class="mt-2 grid gap-4 md:grid-cols-3">
					<div class="md:col-span-2">
						<div class="text-xs text-slate-500">{m.overview.wgDevices}</div>
						<div class="mt-1 flex flex-wrap gap-6">
							{#each wgFigures as st (st)}
								{@const link = wgLinks[st]}
								{#if link}
									<a href={link.href} title={link.title} class="block hover:underline">
										<div class="text-2xl font-semibold tabular-nums {stateText[st]}">
											{wg.totals.device[st].toLocaleString()}
										</div>
										<div class="text-xs text-slate-500">{m.wireguard.stateNames[st]}</div>
									</a>
								{:else}
									<div>
										<div class="text-2xl font-semibold tabular-nums {stateText[st]}">
											{wg.totals.device[st].toLocaleString()}
										</div>
										<div class="text-xs text-slate-500">{m.wireguard.stateNames[st]}</div>
									</div>
								{/if}
							{/each}
						</div>
						<div class="mt-2 text-sm text-slate-600">
							{#if wg.totals.client.total === 0}
								{m.overview.wgNoClients}
							{:else}
								{m.overview.wgClients(
									stateParts(wg.totals.client)
										.map((p) => `${p.n} ${m.wireguard.stateNames[p.state]}`)
										.join(' · ')
								)}
							{/if}
						</div>
					</div>
					<ul class="space-y-1 text-sm">
						{#each wg.networks as n (n.id)}
							<li>
								<a href="/wireguard/networks/{n.id}" class="text-teal-800 hover:underline"
									>{n.name}</a
								>
								<span class="text-xs">
									{#each stateParts(n.device, n.client) as p, i (p.state)}{#if i > 0}
											·
										{/if}<span class={stateText[p.state]}
											>{p.n} {m.wireguard.stateNames[p.state]}</span
										>{/each}
								</span>
							</li>
						{/each}
					</ul>
				</div>
			{/if}
		</div>
	{/if}

	<div class="{card} mt-4">
		<div class="text-sm text-slate-500">{m.overview.versions}</div>
		<div class="mt-2 grid gap-1">
			{#each o.versions as v (v.version)}
				<div class="flex items-center gap-3 text-sm">
					<span class="w-40 truncate font-mono">{v.version}</span>
					<div class="h-2 flex-1 rounded bg-slate-100">
						<div class="h-2 rounded bg-sky-600" style="width: {pct(v.n, o.active)}%"></div>
					</div>
					<span class="w-12 text-right tabular-nums text-slate-600 md:w-24"
						>{v.n.toLocaleString()}</span
					>
				</div>
			{/each}
		</div>
	</div>
{/if}
