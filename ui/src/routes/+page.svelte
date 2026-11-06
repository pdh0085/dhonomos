<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		api,
		ago,
		download,
		type BundleResult,
		type DeleteResult,
		type Device,
		type DeviceFacets,
		type FacetValue
	} from '$lib/api';
	import { agentEndpointId } from '$lib/devicelist';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import AddDevices from '$lib/components/AddDevices.svelte';
	import AttributeImport from '$lib/components/AttributeImport.svelte';
	import CertificateBundle from '$lib/components/CertificateBundle.svelte';
	import DeleteDevices from '$lib/components/DeleteDevices.svelte';
	import { session } from '$lib/session.svelte';
	import { m } from '$lib/messages';

	const PAGE = 100;
	let devices = $state<Device[] | null>(null);
	let total = $state(0);
	let offset = $state(0);
	let error = $state<unknown>(null);
	let q = $state('');
	let protocol = $state('');
	let status = $state('');
	// Exact OUI, product class, model.
	// Options + counts from server; each narrowed by all other filters.
	let oui = $state('');
	let productClass = $state('');
	let model = $state('');
	let facets = $state<DeviceFacets | null>(null);
	// `key=value`; applied on Enter or blur.
	let attrInput = $state('');
	let attr = $state('');
	// Filter expression; applied on Enter or blur.
	// Link may set it: `?filter=` (e.g. Overview WireGuard figures).
	let filterInput = $state(page.url.searchParams.get('filter')?.trim() ?? '');
	let filter = $state(page.url.searchParams.get('filter')?.trim() ?? '');
	let debounced = $state('');
	// Retired devices hidden unless asked; choice in URL (`?retired=1`).
	let showRetired = $state(page.url.searchParams.get('retired') === '1');
	// Status picked in status filter -> it decides, retired or not.
	const hideRetired = $derived(!showRetired && status === '');
	// Only devices with live XMPP session; also in URL (`?xmpp=1`).
	let xmppOnly = $state(page.url.searchParams.get('xmpp') === '1');
	// Hide via server filter, not page trim -> paging stays right.
	const effectiveFilter = $derived.by(() => {
		const also = [
			...(hideRetired ? ['status != retired'] : []),
			...(xmppOnly ? ['xmpp_connected = true'] : [])
		];
		if (also.length === 0) return filter;
		return [...(filter ? [`(${filter})`] : []), ...also].join(' and ');
	});

	function flagsChanged() {
		offset = 0;
		const url = new URL(page.url);
		if (showRetired) url.searchParams.set('retired', '1');
		else url.searchParams.delete('retired');
		if (xmppOnly) url.searchParams.set('xmpp', '1');
		else url.searchParams.delete('xmpp');
		goto(url, { replaceState: true, keepFocus: true, noScroll: true });
	}

	// Debounce 300 ms -> search as you type, no request per keystroke.
	$effect(() => {
		const value = q;
		const t = setTimeout(() => {
			debounced = value;
			offset = 0;
		}, 300);
		return () => clearTimeout(t);
	});

	// Selected value missing from options -> keep it (count 0)
	// -> select does not silently show "any".
	function facetOptions(values: FacetValue[] | undefined, selected: string): FacetValue[] {
		const list = values ?? [];
		if (!selected || list.some((v) => v.value === selected)) return list;
		return [{ value: selected, count: 0 }, ...list];
	}

	async function load() {
		const filters = {
			q: debounced,
			protocol,
			status,
			attr,
			filter: effectiveFilter,
			oui,
			product_class: productClass,
			model_name: model
		};
		// Facets = extras: fail -> keep previous ones; list + its own error shown as usual.
		api.deviceFacets(filters).then(
			(f) => (facets = f),
			() => {}
		);
		try {
			const r = await api.devices(filters, PAGE, offset);
			devices = r.items;
			total = r.total;
			// Selection keeps devices as last shown in list.
			for (const d of r.items) if (selected[d.id]) selected[d.id] = d;
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		void [debounced, protocol, status, attr, effectiveFilter, oui, productClass, model, offset];
		load();
		const timer = setInterval(load, 15000);
		return () => clearInterval(timer);
	});

	const cell = 'px-3 py-2';

	// Phones: filter controls on demand; toggle shows count of filters in use.
	let filtersOpen = $state(false);
	const activeFilters = $derived(
		[attr, protocol, status, oui, productClass, model, filter].filter((v) => v !== '').length +
			(showRetired ? 1 : 0) +
			(xmppOnly ? 1 : 0)
	);
	// Filter control classes: desktop always shown, phone stacked full width.
	const fc = $derived(filtersOpen ? 'w-full md:w-auto' : 'hidden md:block');

	// Operators: add devices before first connect.
	// Admins: select devices (kept over paging + refresh) -> issue certs or delete.
	// Certs also for a serial number list or a filter (in dialog).
	const admin = $derived(session.me?.role === 'admin');
	const canAdd = $derived(
		(session.me?.role === 'operator' || session.me?.role === 'admin') && !session.me?.scope
	);
	let selected = $state<Record<string, Device>>({});
	let addOpen = $state(false);
	let bundleOpen = $state(false);
	let bundleDone = $state<BundleResult | null>(null);
	let deleteOpen = $state(false);
	let deleteDone = $state<DeleteResult | null>(null);
	const selectedDevices = $derived(Object.values(selected));
	// CWMP device -> cert for its USP Agent: os::<OUI>-<serial>.
	// Left out: retired devices + CWMP devices without OUI and serial number.
	const certifiable = $derived(selectedDevices.filter((d) => agentEndpointId(d) !== null));
	const skipped = $derived({
		retired: selectedDevices.filter((d) => d.status === 'retired').length,
		unnamed: selectedDevices.filter((d) => d.status !== 'retired' && agentEndpointId(d) === null)
			.length
	});
	const pageAllSelected = $derived(
		(devices ?? []).length > 0 && (devices ?? []).every((d) => selected[d.id])
	);

	function pick(d: Device, on: boolean) {
		if (on) selected[d.id] = d;
		else delete selected[d.id];
		bundleDone = null;
		deleteDone = null;
	}

	function pickPage(on: boolean) {
		for (const d of devices ?? []) pick(d, on);
	}

	async function exportCsv() {
		const f = new URLSearchParams();
		for (const [k, v] of Object.entries({
			q: debounced,
			protocol,
			status,
			attr,
			filter: effectiveFilter,
			oui,
			product_class: productClass,
			model_name: model
		}))
			if (v.trim()) f.set(k, v.trim());
		try {
			await download(`/devices/export.csv?${f}`, 'devices.csv');
		} catch (e) {
			error = e;
		}
	}
</script>

<div class="mb-4 flex flex-wrap items-center gap-3">
	<h1 class="text-xl font-semibold">{m.devices.title}</h1>
	{#if devices}<span class="text-sm text-slate-500">{m.devices.count(total)}</span>{/if}
	<div class="ml-auto flex w-full flex-wrap gap-2 md:w-auto">
		{#if admin && selectedDevices.length > 0}
			<span class="self-center text-sm text-slate-600"
				>{m.devices.selected(selectedDevices.length)}</span
			>
			<button
				onclick={() => {
					selected = {};
					bundleOpen = false;
					deleteOpen = false;
				}}
				class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
				>{m.devices.clearSelection}</button
			>
			<button
				onclick={() => (deleteOpen = true)}
				class="rounded bg-red-700 px-3 py-1.5 text-sm text-white hover:bg-red-800"
				>{m.devices.remove.action(selectedDevices.length)}</button
			>
		{/if}
		{#if canAdd}
			<button
				onclick={() => (addOpen = true)}
				class="rounded bg-teal-700 px-3 py-1.5 text-sm text-white hover:bg-teal-800"
				>{m.devices.add.action}</button
			>
		{/if}
		{#if admin}
			<button
				onclick={() => (bundleOpen = true)}
				class="rounded bg-teal-700 px-3 py-1.5 text-sm text-white hover:bg-teal-800"
				>{m.devices.bundle.action}</button
			>
		{/if}
		{#if !session.me?.scope}<AttributeImport ondone={load} />{/if}
		<button
			onclick={exportCsv}
			class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
			>{m.common.exportCsv}</button
		>
		<input
			bind:value={q}
			placeholder={m.devices.filter}
			class="w-full rounded border-slate-300 text-sm md:w-72"
		/>
		<button
			type="button"
			onclick={() => (filtersOpen = !filtersOpen)}
			aria-expanded={filtersOpen}
			class="rounded border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-100 md:hidden"
			>{m.devices.filters(activeFilters)}</button
		>
		<input
			bind:value={attrInput}
			onchange={() => {
				const v = attrInput.trim();
				attr = v.includes('=') ? v : '';
				offset = 0;
			}}
			placeholder={m.devices.attrFilter}
			title={m.devices.attrFilter}
			class="{filtersOpen
				? 'w-full'
				: 'hidden md:block'} rounded border-slate-300 font-mono text-sm md:w-52"
		/>
		<select
			bind:value={protocol}
			onchange={() => (offset = 0)}
			class="{fc} rounded border-slate-300 text-sm"
		>
			<option value="">{m.devices.anyProtocol}</option>
			<option value="cwmp">CWMP</option>
			<option value="usp">USP</option>
		</select>
		<select
			bind:value={status}
			onchange={() => (offset = 0)}
			class="{fc} rounded border-slate-300 text-sm"
		>
			<option value="">{m.devices.anyStatus}</option>
			{#each ['active', 'quarantined', 'retired'] as st (st)}<option value={st}>{st}</option>{/each}
		</select>
		<select
			bind:value={oui}
			onchange={() => (offset = 0)}
			class="{fc} rounded border-slate-300 text-sm md:max-w-56"
		>
			<option value="">{m.devices.anyOui}</option>
			{#each facetOptions(facets?.oui, oui) as v (v.value)}<option value={v.value}
					>{m.devices.facetOption(v.value, v.count, v.manufacturer)}</option
				>{/each}
		</select>
		<select
			bind:value={productClass}
			onchange={() => (offset = 0)}
			class="{fc} rounded border-slate-300 text-sm md:max-w-56"
		>
			<option value="">{m.devices.anyProductClass}</option>
			{#each facetOptions(facets?.product_class, productClass) as v (v.value)}<option
					value={v.value}>{m.devices.facetOption(v.value, v.count)}</option
				>{/each}
		</select>
		<select
			bind:value={model}
			onchange={() => (offset = 0)}
			class="{fc} rounded border-slate-300 text-sm md:max-w-56"
		>
			<option value="">{m.devices.anyModel}</option>
			{#each facetOptions(facets?.model_name, model) as v (v.value)}<option value={v.value}
					>{m.devices.facetOption(v.value, v.count)}</option
				>{/each}
		</select>
		<label
			class="{filtersOpen
				? 'flex w-full py-2 md:w-auto md:py-0'
				: 'hidden md:flex'} items-center gap-1.5 text-sm"
			title={m.devices.showRetiredHelp}
			><input type="checkbox" bind:checked={showRetired} onchange={flagsChanged} />{m.devices
				.showRetired}</label
		>
		<label
			class="{filtersOpen
				? 'flex w-full py-2 md:w-auto md:py-0'
				: 'hidden md:flex'} items-center gap-1.5 text-sm"
			title={m.devices.xmppOnlyHelp}
			><input type="checkbox" bind:checked={xmppOnly} onchange={flagsChanged} />{m.devices
				.xmppOnly}</label
		>
		<button
			onclick={load}
			class="{filtersOpen
				? 'py-1.5 md:py-0'
				: 'hidden md:block'} rounded border border-slate-300 bg-white px-3 text-sm hover:bg-slate-100"
			>{m.common.refresh}</button
		>
	</div>
	<input
		bind:value={filterInput}
		onchange={() => {
			filter = filterInput.trim();
			offset = 0;
		}}
		placeholder={m.devices.expression}
		title={m.devices.expressionHelp}
		class="{filtersOpen ? '' : 'hidden md:block'} w-full rounded border-slate-300 font-mono text-sm"
	/>
	{#if addOpen && canAdd}
		<AddDevices onclose={() => (addOpen = false)} ondone={load} />
	{/if}
	{#if bundleOpen && admin}
		<CertificateBundle
			ids={certifiable.map((d) => d.id)}
			{skipped}
			{filter}
			oncancel={() => (bundleOpen = false)}
			ondone={(result) => {
				selected = {};
				bundleOpen = false;
				bundleDone = result;
				deleteDone = null;
				load();
			}}
		/>
	{/if}
	{#if deleteOpen && admin}
		<DeleteDevices
			devices={selectedDevices}
			oncancel={() => (deleteOpen = false)}
			ondone={(result) => {
				selected = {};
				deleteOpen = false;
				deleteDone = result;
				bundleDone = null;
				// Current page may be gone.
				if (offset > 0) offset = 0;
				else load();
			}}
		/>
	{/if}
	{#if bundleDone}
		<p
			class="basis-full rounded-md border border-teal-200 bg-teal-50 px-3 py-2 text-sm text-teal-900"
		>
			{m.devices.bundle.done(bundleDone.name, bundleDone.issued, bundleDone.created)}
		</p>
	{/if}
	{#if deleteDone}
		<p
			class="basis-full rounded-md border border-teal-200 bg-teal-50 px-3 py-2 text-sm text-teal-900"
		>
			{m.devices.remove.done(deleteDone.deleted, deleteDone.certificates_revoked, deleteDone.files)}
		</p>
	{/if}
</div>

{#if error}
	<ErrorBox {error} onretry={load} />
{:else if devices === null}
	<p class="text-slate-500">{m.common.loading}</p>
{:else if devices.length === 0}
	<p class="text-slate-500">
		{m.devices.empty}
		{#if hideRetired}{m.devices.retiredHidden}{/if}
		{#if xmppOnly}{m.devices.xmppOnlyActive}{/if}
	</p>
{:else}
	<!-- Phones: one card per device; whole card opens device. -->
	<div class="md:hidden">
		{#if admin}
			<label class="mb-2 flex items-center gap-2 py-1 text-sm text-slate-600"
				><input
					type="checkbox"
					checked={pageAllSelected}
					onchange={(e) => pickPage(e.currentTarget.checked)}
				/>{m.devices.selectPage}</label
			>
		{/if}
		<ul class="space-y-2">
			{#each devices as d (d.id)}
				<li class="flex items-start gap-3 rounded-md border border-slate-200 bg-white p-3">
					{#if admin}<input
							type="checkbox"
							class="mt-1"
							aria-label={m.devices.selectOne}
							checked={!!selected[d.id]}
							onchange={(e) => pick(d, e.currentTarget.checked)}
						/>{/if}
					<a href="/devices/{d.id}" class="block min-w-0 flex-1 space-y-1 text-sm">
						<span class="flex flex-wrap items-center gap-2">
							<span class="font-mono break-all text-teal-800"
								>{d.serial_number ?? d.endpoint_id}</span
							>
							<span class="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700 uppercase"
								>{d.protocol}</span
							>
							{#if d.xmpp_connected_at}<span
									class="rounded bg-sky-100 px-1.5 py-0.5 text-xs text-sky-800"
									title={m.devices.xmppBadgeTitle(new Date(d.xmpp_connected_at).toLocaleString())}
									>{m.devices.xmppBadge}</span
								>{/if}
						</span>
						<span class="block break-words text-slate-800"
							>{d.model_name ?? d.product_class ?? m.common.none} ·
							<span class="font-mono">{d.software_version ?? m.common.none}</span></span
						>
						<span class="block text-xs break-words text-slate-500"
							>{ago(d.last_contact_at, m.common.never)} · {d.status}{#if d.last_remote_addr}{' · '}<span
									class="font-mono break-all">{d.last_remote_addr}</span
								>{/if}</span
						>
					</a>
				</li>
			{/each}
		</ul>
	</div>
	<div class="hidden overflow-x-auto rounded-md border border-slate-200 bg-white md:block">
		<table class="min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					{#if admin}<th class={cell}
							><input
								type="checkbox"
								aria-label={m.devices.selectPage}
								title={m.devices.selectPage}
								checked={pageAllSelected}
								onchange={(e) => pickPage(e.currentTarget.checked)}
							/></th
						>{/if}
					<th class={cell}>{m.devices.serial}</th>
					<th class={cell}>{m.devices.protocol}</th>
					<th class={cell}>{m.devices.oui}</th>
					<th class={cell}>{m.devices.productClass}</th>
					<th class={cell}>{m.devices.model}</th>
					<th class={cell}>{m.devices.software}</th>
					<th class={cell}>{m.devices.lastContact}</th>
					<th class={cell}>{m.devices.address}</th>
					<th class={cell}>{m.devices.status}</th>
				</tr>
			</thead>
			<tbody>
				{#each devices as d (d.id)}
					<tr class="border-t border-slate-100 hover:bg-teal-50">
						{#if admin}<td class={cell}
								><input
									type="checkbox"
									aria-label={m.devices.selectOne}
									title={m.devices.selectOne}
									checked={!!selected[d.id]}
									onchange={(e) => pick(d, e.currentTarget.checked)}
								/></td
							>{/if}
						<td class="{cell} font-mono"
							><a class="text-teal-800 hover:underline" href="/devices/{d.id}"
								>{d.serial_number ?? d.endpoint_id}</a
							>{#if d.xmpp_connected_at}<span
									class="ml-2 rounded bg-sky-100 px-1.5 py-0.5 font-sans text-xs text-sky-800"
									title={m.devices.xmppBadgeTitle(new Date(d.xmpp_connected_at).toLocaleString())}
									>{m.devices.xmppBadge}</span
								>{/if}</td
						>
						<td class={cell}
							><span class="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700 uppercase"
								>{d.protocol}</span
							></td
						>
						<td class="{cell} font-mono">{d.oui ?? m.common.none}</td>
						<td class={cell}>{d.product_class || m.common.none}</td>
						<td class={cell}>{d.model_name ?? m.common.none}</td>
						<td class="{cell} font-mono">{d.software_version ?? m.common.none}</td>
						<td class={cell} title={d.last_contact_at ?? ''}
							>{ago(d.last_contact_at, m.common.never)}</td
						>
						<td class="{cell} font-mono">{d.last_remote_addr ?? m.common.none}</td>
						<td class={cell}>{d.status}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<div class="mt-3 flex flex-wrap items-center justify-end gap-3 text-sm">
		<span class="text-slate-500"
			>{m.devices.range(offset + 1, Math.min(offset + PAGE, total), total)}</span
		>
		<button
			disabled={offset === 0}
			onclick={() => (offset = Math.max(0, offset - PAGE))}
			class="rounded border border-slate-300 bg-white px-3 py-1 hover:bg-slate-100 disabled:opacity-40"
			>{m.devices.previous}</button
		>
		<button
			disabled={offset + PAGE >= total}
			onclick={() => (offset += PAGE)}
			class="rounded border border-slate-300 bg-white px-3 py-1 hover:bg-slate-100 disabled:opacity-40"
			>{m.devices.next}</button
		>
	</div>
{/if}
