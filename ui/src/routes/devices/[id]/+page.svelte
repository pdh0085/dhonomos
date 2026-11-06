<script lang="ts">
	import { page } from '$app/state';
	import {
		api,
		ago,
		type Device,
		type DeviceEvent,
		type Parameter,
		type ScriptTrace as ScriptTraceData,
		type Task
	} from '$lib/api';
	import ScriptTrace from '$lib/components/ScriptTrace.svelte';
	import DeviceLabels from '$lib/components/DeviceLabels.svelte';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import BackupsPanel from '$lib/components/BackupsPanel.svelte';
	import CertificatesPanel from '$lib/components/CertificatesPanel.svelte';
	import ConnectionRequestCard from '$lib/components/ConnectionRequestCard.svelte';
	import MetricsPanel from '$lib/components/MetricsPanel.svelte';
	import WifiPanel from '$lib/components/WifiPanel.svelte';
	import WireGuardPanel from '$lib/components/WireGuardPanel.svelte';
	import { goto } from '$app/navigation';
	import TaskForm from '$lib/components/TaskForm.svelte';
	import TaskDetail from '$lib/components/TaskDetail.svelte';
	import ParameterTree from '$lib/components/ParameterTree.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';

	const id = $derived(page.params.id ?? '');
	type Tab =
		| 'parameters'
		| 'tasks'
		| 'events'
		| 'wifi'
		| 'metrics'
		| 'backups'
		| 'certificates'
		| 'wireguard';
	let tab = $state<Tab>(page.url.searchParams.get('task') ? 'tasks' : 'parameters');
	let device = $state<Device | null>(null);
	let params = $state<Parameter[]>([]);
	let tasks = $state<Task[]>([]);
	// Certificates: USP Agents only. WireGuard: operator and up (= navigation).
	const tabs = $derived<Tab[]>([
		'parameters',
		'tasks',
		'events',
		'wifi',
		'metrics',
		'backups',
		...(device?.protocol === 'usp' ? (['certificates'] as const) : []),
		...(session.me && session.me.role !== 'viewer' ? (['wireguard'] as const) : [])
	]);
	// `?task=<id>` -> open details of that task.
	let openTask = $state<string | null>(page.url.searchParams.get('task'));
	let events = $state<DeviceEvent[]>([]);
	let error = $state<unknown>(null);
	let notice = $state('');

	const root = $derived(device?.data_model ?? 'Device');

	async function load() {
		error = null;
		try {
			const [d, p, t, e] = await Promise.all([
				api.device(id),
				api.parameters(id, ''),
				api.tasks(id),
				api.events(id)
			]);
			device = d;
			params = p;
			tasks = t;
			events = e;
		} catch (err) {
			error = err;
		}
	}

	$effect(() => {
		load();
		const timer = setInterval(load, 5000);
		return () => clearInterval(timer);
	});

	// Live events via SSE (cookie sessions only).
	$effect(() => {
		if (!id || typeof EventSource === 'undefined') return;
		const es = new EventSource(`/api/v1/stream?device_id=${id}`);
		es.addEventListener('device_event', (msg) => {
			const ev = JSON.parse((msg as MessageEvent).data) as DeviceEvent;
			if (!events.some((e) => e.id === ev.id)) events = [ev, ...events].slice(0, 200);
		});
		return () => es.close();
	});

	// USP Agents: run queued tasks now. CWMP -> Connection request card.
	async function wake() {
		try {
			notice = m.device.wakeResult((await api.wake(id)).connection_request);
		} catch (err) {
			notice = String(err);
		}
		await load();
	}

	async function setStatus(status: string) {
		if (status === 'retired' && !confirm(m.device.confirmRetire)) return;
		try {
			device = await api.setStatus(id, status);
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	async function replace() {
		const who = prompt(m.device.replacePrompt)?.trim();
		if (!who) return;
		try {
			const found = (await api.devices({ q: who }, 50)).items;
			const target = found.find((d) => d.serial_number === who || d.endpoint_id === who);
			if (!target) {
				notice = m.device.replaceNotFound(who);
				return;
			}
			notice = m.device.replaced((await api.replaceDevice(id, target.id)).tasks.length);
			await load();
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	async function remove() {
		if (!confirm(m.device.confirmDelete)) return;
		try {
			await api.deleteDevice(id);
			await goto('/');
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	async function cancel(taskId: string) {
		try {
			await api.cancelTask(taskId);
			await load();
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	const stateColor: Record<string, string> = {
		pending: 'bg-amber-100 text-amber-800',
		running: 'bg-sky-100 text-sky-800',
		succeeded: 'bg-emerald-100 text-emerald-800',
		failed: 'bg-red-100 text-red-800',
		cancelled: 'bg-slate-200 text-slate-700',
		expired: 'bg-slate-200 text-slate-700'
	};
</script>

<a href="/" class="text-sm text-teal-800 hover:underline">← {m.common.back}</a>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !device}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else}
	<section class="mt-3 rounded-md border border-slate-200 bg-white p-4">
		<div class="flex flex-wrap items-start gap-4">
			<div class="min-w-0">
				<h1 class="font-mono text-xl font-semibold break-all md:break-normal">
					{device.serial_number ?? device.endpoint_id}
				</h1>
				<p class="text-sm text-slate-600">
					{device.manufacturer ?? ''}
					{device.model_name ?? device.product_class}
				</p>
			</div>
			<div class="flex flex-wrap items-center gap-2 md:ml-auto">
				<span
					class="rounded px-2 py-0.5 text-xs {device.status === 'active'
						? 'bg-emerald-100 text-emerald-800'
						: device.status === 'quarantined'
							? 'bg-amber-100 text-amber-800'
							: 'bg-slate-200 text-slate-700'}">{device.status}</span
				>
				{#each ['active', 'quarantined', 'retired'].filter((st) => st !== device?.status) as st (st)}
					<button
						onclick={() => setStatus(st)}
						class="rounded border border-slate-300 px-2 py-1 text-xs hover:bg-slate-100"
						>{m.device.setStatus[st]}</button
					>
				{/each}
				{#if device.status === 'active'}
					<button
						onclick={replace}
						class="rounded border border-slate-300 px-2 py-1 text-xs hover:bg-slate-100"
						>{m.device.replace}</button
					>
				{:else if device.status === 'retired'}
					<button
						onclick={remove}
						class="rounded border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50"
						>{m.device.delete}</button
					>
				{/if}
				{#if device.protocol === 'usp'}
					<button
						onclick={wake}
						class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
						>{m.device.wakeUsp}</button
					>
				{/if}
			</div>
		</div>
		<dl class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-4">
			{#if device.endpoint_id}
				<div class="col-span-2">
					<dt class="text-slate-500">{m.device.endpointId}</dt>
					<dd class="font-mono break-all">{device.endpoint_id}</dd>
				</div>
			{/if}
			<div>
				<dt class="text-slate-500">{m.devices.oui}</dt>
				<dd class="font-mono">{device.oui}</dd>
			</div>
			<div>
				<dt class="text-slate-500">{m.devices.software}</dt>
				<dd class="font-mono">{device.software_version ?? m.common.none}</dd>
			</div>
			<div>
				<dt class="text-slate-500">{m.device.dataModel}</dt>
				<dd>{device.data_model ?? m.common.none}</dd>
			</div>
			<div>
				<dt class="text-slate-500">{m.devices.address}</dt>
				<dd class="font-mono break-all md:break-normal">
					{device.last_remote_addr ?? m.common.none}
				</dd>
			</div>
			<div>
				<dt class="text-slate-500">{m.devices.lastContact}</dt>
				<dd>{ago(device.last_contact_at, m.common.never)}</dd>
			</div>
			<div>
				<dt class="text-slate-500">{m.device.lastBoot}</dt>
				<dd>{ago(device.last_boot_at, m.common.never)}</dd>
			</div>
			<div>
				<dt class="text-slate-500">{m.device.firstSeen}</dt>
				<dd>{ago(device.first_seen_at)}</dd>
			</div>
		</dl>
		<DeviceLabels {device} onsaved={(d) => (device = d)} />
		{#if notice}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm">{notice}</p>{/if}
	</section>

	{#if device.protocol === 'cwmp'}
		<ConnectionRequestCard {device} {params} onchanged={load} />
	{/if}

	<!-- Phone: tabs scroll sideways in their row -> page width stays. -->
	<div
		class="mt-4 flex gap-1 overflow-x-auto border-b border-slate-200 md:overflow-visible"
		role="tablist"
	>
		{#each tabs as t (t)}
			<button
				role="tab"
				aria-selected={tab === t}
				onclick={(e) => {
					tab = t;
					e.currentTarget.scrollIntoView({ inline: 'nearest', block: 'nearest' });
				}}
				class="shrink-0 border-b-2 px-4 py-2 text-sm whitespace-nowrap md:-mb-px {tab === t
					? 'border-teal-700 font-medium text-teal-800'
					: 'border-transparent text-slate-600 hover:text-slate-900'}"
			>
				{m.device.tabs[t]}
				<span class="ml-1 text-xs text-slate-400"
					>{t === 'parameters'
						? params.length
						: t === 'tasks'
							? tasks.length
							: t === 'events'
								? events.length
								: ''}</span
				>
			</button>
		{/each}
	</div>

	{#if tab === 'parameters'}
		<ParameterTree deviceId={id} protocol={device.protocol} {params} onchanged={load} />
	{:else if tab === 'tasks'}
		<h2 class="mt-4 mb-2 text-sm font-medium text-slate-700">{m.tasks.create}</h2>
		<TaskForm
			deviceId={id}
			{root}
			protocol={device.protocol}
			oncreated={(msg) => {
				notice = msg;
				load();
			}}
		/>
		{#if tasks.length === 0}
			<p class="mt-4 text-slate-500">{m.tasks.empty}</p>
		{:else}
			<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="stack min-w-full text-sm">
					<thead class="bg-slate-100 text-left text-slate-600">
						<tr
							><th class="px-3 py-2">{m.tasks.kind}</th><th class="px-3 py-2">{m.tasks.state}</th
							><th class="px-3 py-2">{m.tasks.attempts}</th><th class="px-3 py-2"
								>{m.tasks.result}</th
							><th class="px-3 py-2">{m.tasks.created}</th><th></th></tr
						>
					</thead>
					<tbody>
						{#each tasks as t (t.id)}
							<tr class="border-t border-slate-100 align-top">
								<td class="px-3 py-2"
									><div class="min-w-0">
										{m.tasks.kinds[t.kind] ?? t.kind}
										{#if t.job_id}<a
												href="/jobs/{t.job_id}"
												class="ml-1 text-xs text-teal-800 hover:underline">{m.tasks.viaJob}</a
											>{:else if t.created_by && t.created_by !== 'api'}<span
												class="ml-1 text-xs text-slate-400">{t.created_by}</span
											>{/if}
										<div
											class="line-clamp-3 font-mono text-xs break-all text-slate-500 md:line-clamp-none md:break-normal"
										>
											{JSON.stringify(t.payload)}
										</div>
									</div></td
								>
								<td class="px-3 py-2" data-label={m.tasks.state}
									><span class="rounded px-2 py-0.5 text-xs {stateColor[t.state] ?? ''}"
										>{t.state}</span
									></td
								>
								<td class="px-3 py-2" data-label={m.tasks.attempts}
									>{t.attempts}/{t.max_attempts}</td
								>
								<td
									class="max-w-sm px-3 py-2 font-mono text-xs break-all"
									data-label={m.tasks.result}
									>{t.error ?? (t.result ? JSON.stringify(t.result) : '')}</td
								>
								<td
									class="px-3 py-2 text-slate-500"
									title={t.created_at}
									data-label={m.tasks.created}>{ago(t.created_at)}</td
								>
								<td class="px-3 py-2 whitespace-nowrap"
									><button
										onclick={() => (openTask = openTask === t.id ? null : t.id)}
										class="py-2 text-xs text-teal-800 hover:underline md:py-0"
										>{openTask === t.id ? m.tasks.hide : m.tasks.details}</button
									>{#if t.state === 'pending'}<button
											onclick={() => cancel(t.id)}
											class="ml-3 py-2 text-xs text-red-700 hover:underline md:py-0"
											>{m.tasks.cancel}</button
										>{/if}</td
								>
							</tr>
							{#if openTask === t.id}
								<tr class="bg-slate-50/50">
									<td colspan="6" class="px-3 py-3"
										><div class="min-w-0 flex-1"><TaskDetail task={t} /></div></td
									>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'wifi'}
		<WifiPanel deviceId={id} {root} />
	{:else if tab === 'backups'}
		<BackupsPanel deviceId={id} />
	{:else if tab === 'certificates'}
		<CertificatesPanel deviceId={id} />
	{:else if tab === 'metrics'}
		<MetricsPanel deviceId={id} />
	{:else if tab === 'wireguard'}
		<WireGuardPanel deviceId={id} />
	{:else if events.length === 0}
		<p class="mt-3 text-slate-500">{m.events.empty}</p>
	{:else}
		<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600"
					><tr
						><th class="px-3 py-2">{m.events.when}</th><th class="px-3 py-2">{m.events.kind}</th><th
							class="px-3 py-2">{m.events.detail}</th
						></tr
					></thead
				>
				<tbody>
					{#each events as e (e.id)}
						<tr class="border-t border-slate-100 align-top">
							<td class="px-3 py-2 text-slate-500" title={e.occurred_at} data-label={m.events.when}
								>{ago(e.occurred_at)}</td
							>
							<td class="px-3 py-2" data-label={m.events.kind}>{e.kind}</td>
							<td class="px-3 py-2 font-mono text-xs" data-label={m.events.detail}>
								{#if e.kind === 'script'}
									<div class="min-w-0 font-sans">
										<ScriptTrace trace={e.detail as unknown as ScriptTraceData} />
									</div>
								{:else}
									{JSON.stringify(e.detail)}
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
{/if}
