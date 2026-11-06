<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, type Device, type DeviceFilter, type StoredFile } from '$lib/api';
	import { m } from '$lib/messages';

	let name = $state('');
	let protocol = $state('');
	let oui = $state('');
	let productClass = $state('');
	let versions = $state('');
	let tags = $state('');
	let expression = $state('');
	let attributes = $state('');

	const kinds = [
		'reboot',
		'download',
		'set_parameter_values',
		'get_parameter_values',
		'factory_reset',
		'operate'
	];
	let kind = $state('reboot');
	let fileId = $state('');
	let files = $state<StoredFile[]>([]);
	let param = $state('');
	let value = $state('');
	let type = $state('string');
	let path = $state('Device.DeviceInfo.');
	let command = $state('');
	let inputs = $state('');

	let canary = $state(true);
	let maxInFlight = $state(200);
	let batchSize = $state(100);
	let abortRate = $state<number | null>(10);
	let gateRate = $state<number | null>(95);
	let autoAdvance = $state(true);
	let verifyVersion = $state('');
	let verifyMinutes = $state(30);
	let expiryHours = $state(24);
	let windowStart = $state('');
	let windowEnd = $state('');
	let utcOffset = $state(0);

	let preview = $state<{ count: number; sample: Device[] } | null>(null);
	let error = $state('');
	let busy = $state(false);

	$effect(() => {
		if (kind === 'download' && files.length === 0) {
			api
				.files()
				.then((f) => {
					files = f;
					if (!fileId && f.length > 0) fileId = f[0].id;
				})
				.catch(() => (files = []));
		}
	});

	const list = (s: string) =>
		s
			.split(',')
			.map((x) => x.trim())
			.filter(Boolean);

	function target(): DeviceFilter {
		const t: DeviceFilter = {};
		if (protocol) t.protocol = protocol;
		if (oui.trim()) t.oui = oui.trim();
		if (productClass.trim()) t.product_class = productClass.trim();
		if (list(versions).length) t.software_version = list(versions);
		if (list(tags).length) t.tags = list(tags);
		// `key=value, key=value`
		const attrs = Object.fromEntries(
			list(attributes)
				.map((kv) => kv.split('='))
				.filter((p) => p.length === 2 && p[0].trim())
				.map(([k, v]) => [k.trim(), v.trim()])
		);
		if (Object.keys(attrs).length) t.attributes = attrs;
		if (expression.trim()) t.expression = expression.trim();
		return t;
	}

	function task() {
		switch (kind) {
			case 'download':
				return { kind, payload: { file_id: fileId } };
			case 'set_parameter_values':
				return { kind, payload: { values: [{ name: param, value, type }] } };
			case 'get_parameter_values':
				return { kind, payload: { names: [path] } };
			case 'operate':
				return {
					kind,
					payload: {
						command,
						input: Object.fromEntries(
							inputs
								.split('\n')
								.map((l) => l.split('='))
								.filter((p) => p.length === 2 && p[0].trim())
								.map(([k, v]) => [k.trim(), v.trim()])
						)
					}
				};
			default:
				return { kind };
		}
	}

	function policy() {
		const p: Record<string, unknown> = {
			stages: canary ? [1, 10, 100] : [100],
			max_in_flight: maxInFlight,
			batch_size: batchSize,
			auto_advance: autoAdvance,
			task: { max_attempts: 2, expires_in_seconds: Math.round(expiryHours * 3600) }
		};
		if (abortRate !== null) p.abort_failure_rate = abortRate;
		if (gateRate !== null) p.gate_success_rate = gateRate;
		if (verifyVersion.trim())
			p.verify = { software_version: verifyVersion.trim(), within_seconds: verifyMinutes * 60 };
		if (windowStart && windowEnd)
			p.window = { start: windowStart, end: windowEnd, utc_offset_minutes: utcOffset };
		return p;
	}

	async function runPreview() {
		error = '';
		try {
			preview = await api.previewJob(target());
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	}

	async function submit(start: boolean) {
		busy = true;
		error = '';
		try {
			const job = await api.createJob({
				name,
				target: target(),
				task: task(),
				policy: policy(),
				start
			});
			await goto(`/jobs/${job.id}`);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = false;
		}
	}

	const input = 'w-full rounded border-slate-300 text-sm';
	const label = 'mb-1 block text-slate-600';
</script>

<a href="/jobs" class="text-sm text-teal-800 hover:underline">← {m.jobs.back}</a>
<h1 class="mt-2 text-xl font-semibold">{m.jobs.create}</h1>

<form
	class="mt-4 grid gap-4"
	onsubmit={(e) => {
		e.preventDefault();
		submit(true);
	}}
>
	<label class="text-sm">
		<span class={label}>{m.jobs.name}</span>
		<input bind:value={name} required class={input} />
	</label>

	<fieldset class="rounded-md border border-slate-200 bg-white p-4">
		<legend class="px-1 text-sm font-medium">{m.jobs.target}</legend>
		<div class="grid gap-3 md:grid-cols-5">
			<label class="text-sm">
				<span class={label}>{m.devices.protocol}</span>
				<select bind:value={protocol} class={input}>
					<option value="">{m.jobs.anyProtocol}</option>
					<option value="cwmp">CWMP</option>
					<option value="usp">USP</option>
				</select>
			</label>
			<label class="text-sm"
				><span class={label}>{m.jobs.oui}</span><input bind:value={oui} class={input} /></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.productClass}</span><input
					bind:value={productClass}
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.versions}</span><input
					bind:value={versions}
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.tags}</span><input bind:value={tags} class={input} /></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.attributes}</span><input
					bind:value={attributes}
					placeholder="plan=gold"
					class="{input} font-mono"
				/></label
			>
			<label class="text-sm md:col-span-3"
				><span class={label}>{m.jobs.expression}</span><input
					bind:value={expression}
					class="{input} font-mono"
				/><span class="text-xs text-slate-500">{m.jobs.expressionHint}</span></label
			>
		</div>
		<div class="mt-3 flex flex-wrap items-center gap-3 md:flex-nowrap">
			<button
				type="button"
				onclick={runPreview}
				class="rounded border border-slate-300 px-3 py-2.5 text-sm hover:bg-slate-100 md:py-1.5"
				>{m.jobs.preview}</button
			>
			{#if preview}
				<span class="text-sm font-medium">{m.jobs.matches(preview.count)}</span>
				<span class="w-full truncate font-mono text-xs text-slate-500 md:w-auto"
					>{preview.sample
						.slice(0, 8)
						.map((d) => d.serial_number ?? d.endpoint_id)
						.join(', ')}</span
				>
			{/if}
		</div>
	</fieldset>

	<fieldset class="rounded-md border border-slate-200 bg-white p-4">
		<legend class="px-1 text-sm font-medium">{m.jobs.task}</legend>
		<div class="grid gap-3 md:grid-cols-4">
			<label class="text-sm">
				<span class={label}>{m.tasks.kind}</span>
				<select bind:value={kind} class={input}>
					{#each kinds as k (k)}<option value={k}>{m.tasks.kinds[k]}</option>{/each}
				</select>
			</label>
			{#if kind === 'download'}
				<label class="text-sm md:col-span-3">
					<span class={label}>{m.tasks.fields.file}</span>
					{#if files.length === 0}
						<p class="py-2 text-slate-500">{m.tasks.fields.noFiles}</p>
					{:else}
						<select bind:value={fileId} required class={input}>
							{#each files as f (f.id)}
								<option value={f.id}>{f.name}{f.version ? ` (${f.version})` : ''}</option>
							{/each}
						</select>
					{/if}
				</label>
			{:else if kind === 'set_parameter_values'}
				<label class="text-sm"
					><span class={label}>{m.tasks.fields.name}</span><input
						bind:value={param}
						required
						class="{input} font-mono"
					/></label
				>
				<label class="text-sm"
					><span class={label}>{m.tasks.fields.value}</span><input
						bind:value
						class={input}
					/></label
				>
				<label class="text-sm">
					<span class={label}>{m.tasks.fields.type}</span>
					<select bind:value={type} class={input}>
						{#each ['string', 'boolean', 'unsignedInt', 'int', 'dateTime'] as t (t)}<option
								>{t}</option
							>{/each}
					</select>
				</label>
			{:else if kind === 'get_parameter_values'}
				<label class="text-sm md:col-span-3"
					><span class={label}>{m.tasks.fields.path}</span><input
						bind:value={path}
						required
						class="{input} font-mono"
					/></label
				>
			{:else if kind === 'operate'}
				<label class="text-sm md:col-span-2"
					><span class={label}>{m.tasks.fields.command}</span><input
						bind:value={command}
						required
						pattern=".*\(\)$"
						class="{input} font-mono"
					/></label
				>
				<label class="text-sm"
					><span class={label}>{m.tasks.fields.inputs} (name=value)</span><textarea
						bind:value={inputs}
						rows="2"
						class="{input} font-mono"
					></textarea></label
				>
			{/if}
		</div>
	</fieldset>

	<fieldset class="rounded-md border border-slate-200 bg-white p-4">
		<legend class="px-1 text-sm font-medium">{m.jobs.policy}</legend>
		<div class="grid gap-3 md:grid-cols-4">
			<label class="text-sm">
				<span class={label}>{m.jobs.stagesLabel}</span>
				<select bind:value={canary} class={input}>
					<option value={true}>{m.jobs.canary}</option>
					<option value={false}>{m.jobs.allAtOnce}</option>
				</select>
			</label>
			<label class="text-sm"
				><span class={label}>{m.jobs.maxInFlight}</span><input
					type="number"
					min="1"
					bind:value={maxInFlight}
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.batchSize}</span><input
					type="number"
					min="1"
					bind:value={batchSize}
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.expiryHours}</span><input
					type="number"
					min="1"
					bind:value={expiryHours}
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.abortRate}</span><input
					type="number"
					min="0"
					max="100"
					bind:value={abortRate}
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.gateRate}</span><input
					type="number"
					min="0"
					max="100"
					bind:value={gateRate}
					class={input}
				/></label
			>
			<label class="flex items-center gap-2 self-end pb-2 text-sm"
				><input type="checkbox" bind:checked={autoAdvance} />{m.jobs.autoAdvance}</label
			>
			<div class="hidden md:block"></div>
			<label class="text-sm md:col-span-2"
				><span class={label}>{m.jobs.verify}</span><input
					bind:value={verifyVersion}
					class="{input} font-mono"
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.verifyMinutes}</span><input
					type="number"
					min="1"
					bind:value={verifyMinutes}
					class={input}
				/></label
			>
			<div class="hidden md:block"></div>
			<label class="text-sm"
				><span class={label}>{m.jobs.window}: {m.jobs.windowStart}</span><input
					bind:value={windowStart}
					placeholder="01:00"
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.windowEnd}</span><input
					bind:value={windowEnd}
					placeholder="05:00"
					class={input}
				/></label
			>
			<label class="text-sm"
				><span class={label}>{m.jobs.utcOffset}</span><input
					type="number"
					bind:value={utcOffset}
					class={input}
				/></label
			>
		</div>
	</fieldset>

	<div class="flex flex-wrap items-center gap-3 md:flex-nowrap">
		<button
			disabled={busy}
			class="rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 disabled:opacity-50 md:py-2"
			>{m.jobs.start}</button
		>
		<button
			type="button"
			disabled={busy}
			onclick={() => submit(false)}
			class="rounded border border-slate-300 px-4 py-2.5 text-sm hover:bg-slate-100 disabled:opacity-50 md:py-2"
			>{m.jobs.draft}</button
		>
		{#if error}<p class="text-sm text-red-700">{error}</p>{/if}
	</div>
</form>
