<script lang="ts">
	import { api, type AlarmRule, type DeviceFilter, type Silence } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';

	let silences = $state<Silence[] | null>(null);
	let rules = $state<AlarmRule[]>([]);
	let error = $state<unknown>(null);
	let adding = $state(false);
	let busy = $state(false);

	let rule = $state('');
	let productClass = $state('');
	let tag = $state('');
	let deviceId = $state('');
	let duration = $state(60);
	let comment = $state('');

	async function load() {
		try {
			silences = await api.silences();
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
		api.alarmRules().then(
			(r) => (rules = r),
			() => {}
		);
		const timer = setInterval(load, 30000);
		return () => clearInterval(timer);
	});

	function filterText(f: DeviceFilter): string {
		const parts = [
			f.protocol,
			f.oui && `OUI ${f.oui}`,
			f.product_class,
			...(f.software_version ?? []),
			...(f.tags ?? []).map((t) => `#${t}`),
			...(f.device_ids ?? []).map((d) => d.slice(0, 8))
		].filter(Boolean);
		return parts.length ? parts.join(', ') : m.silences.allDevices;
	}

	function when(iso: string): string {
		return new Date(iso).toLocaleString();
	}

	async function create(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const devices: DeviceFilter = {};
			if (productClass.trim()) devices.product_class = productClass.trim();
			if (tag.trim()) devices.tags = [tag.trim()];
			if (deviceId.trim()) devices.device_ids = [deviceId.trim()];
			await api.createSilence({
				rule: rule || undefined,
				devices,
				duration_minutes: duration,
				comment
			});
			adding = false;
			productClass = tag = deviceId = comment = rule = '';
			await load();
		} catch (err) {
			error = err;
		} finally {
			busy = false;
		}
	}

	async function end(id: string) {
		try {
			await api.endSilence(id);
			await load();
		} catch (err) {
			error = err;
		}
	}
</script>

<section class="mt-8">
	<div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between md:gap-4">
		<div>
			<h2 class="text-lg font-semibold">{m.silences.title}</h2>
			<p class="text-sm text-slate-600">{m.silences.intro}</p>
		</div>
		{#if !adding}
			<button
				onclick={() => (adding = true)}
				class="self-start rounded bg-teal-700 px-3 py-2.5 text-sm whitespace-nowrap text-white hover:bg-teal-800 md:self-auto md:py-1.5"
				>{m.silences.add}</button
			>
		{/if}
	</div>

	{#if adding}
		<form
			onsubmit={create}
			class="mt-3 grid gap-3 rounded-md border border-slate-200 bg-white p-4 text-sm sm:grid-cols-3"
		>
			<label class="block"
				><span class="text-slate-600">{m.silences.rule}</span>
				<select bind:value={rule} class="mt-1 w-full rounded border-slate-300 text-sm">
					<option value="">{m.silences.allRules}</option>
					{#each rules as r (r.name)}<option value={r.name}>{r.name}</option>{/each}
				</select></label
			>
			<label class="block"
				><span class="text-slate-600">{m.silences.productClass}</span>
				<input
					bind:value={productClass}
					class="mt-1 w-full rounded border-slate-300 text-sm"
				/></label
			>
			<label class="block"
				><span class="text-slate-600">{m.silences.tag}</span>
				<input bind:value={tag} class="mt-1 w-full rounded border-slate-300 text-sm" /></label
			>
			<label class="block"
				><span class="text-slate-600">{m.silences.deviceId}</span>
				<input
					bind:value={deviceId}
					class="mt-1 w-full rounded border-slate-300 font-mono text-sm"
				/></label
			>
			<label class="block"
				><span class="text-slate-600">{m.silences.duration}</span>
				<select bind:value={duration} class="mt-1 w-full rounded border-slate-300 text-sm">
					{#each m.silences.durations as [minutes, label] (minutes)}<option value={minutes}
							>{label}</option
						>{/each}
				</select></label
			>
			<label class="block"
				><span class="text-slate-600">{m.silences.comment}</span>
				<input
					bind:value={comment}
					placeholder={m.silences.commentHint}
					class="mt-1 w-full rounded border-slate-300 text-sm"
				/></label
			>
			<div class="flex gap-2 sm:col-span-3">
				<button
					disabled={busy}
					class="rounded bg-teal-700 px-3 py-2.5 text-white hover:bg-teal-800 disabled:opacity-50 md:py-1.5"
					>{m.silences.create}</button
				>
				<button
					type="button"
					onclick={() => (adding = false)}
					class="rounded border border-slate-300 px-3 py-2.5 hover:bg-slate-50 md:py-1.5"
					>{m.common.cancel}</button
				>
			</div>
		</form>
	{/if}

	{#if error}
		<div class="mt-3"><ErrorBox {error} onretry={load} /></div>
	{:else if !silences}
		<p class="mt-3 text-slate-500">{m.common.loading}</p>
	{:else if silences.length === 0}
		<p class="mt-3 text-sm text-slate-500">{m.silences.empty}</p>
	{:else}
		<ul class="mt-3 divide-y divide-slate-100 rounded-md border border-slate-200 bg-white text-sm">
			{#each silences as s (s.id)}
				<li class="flex items-start justify-between gap-4 px-3 py-2">
					<div class="min-w-0 [overflow-wrap:anywhere] md:[overflow-wrap:normal]">
						<div>
							<span class="font-medium">{s.rule ?? m.silences.allRules}</span>
							<span class="text-slate-500">· {filterText(s.devices)}</span>
							{#if s.state === 'pending'}<span
									class="ml-1 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600"
									>{m.silences.from(when(s.starts_at))}</span
								>{/if}
						</div>
						<div class="text-xs text-slate-500">
							{m.silences.until(when(s.ends_at))}{#if s.created_by}
								· {m.silences.by(s.created_by)}{/if}{#if s.comment}
								· {s.comment}{/if}
						</div>
					</div>
					<button
						onclick={() => end(s.id)}
						class="shrink-0 py-2 text-xs text-teal-800 hover:underline md:py-0"
						>{m.silences.end}</button
					>
				</li>
			{/each}
		</ul>
	{/if}
</section>
