<script lang="ts">
	import { api, bytes, type StoredFile, type SupportedCommand } from '$lib/api';
	import { m } from '$lib/messages';

	let {
		deviceId,
		root,
		protocol,
		oncreated
	}: {
		deviceId: string;
		root: string;
		protocol: string;
		oncreated: (msg: string) => void;
	} = $props();

	// Tasks per protocol driver.
	const uspKinds = [
		'get_parameter_values',
		'set_parameter_values',
		'add_object',
		'delete_object',
		'reboot',
		'factory_reset',
		'operate',
		'diagnostic'
	];
	const kinds = $derived(
		Object.keys(m.tasks.kinds).filter((k) =>
			protocol === 'usp' ? uspKinds.includes(k) : k !== 'operate'
		)
	);
	let kind = $state('get_parameter_values');
	let path = $state('');
	let name = $state('');
	let value = $state('');
	let type = $state('string');
	let secret = $state(false);
	let url = $state('');
	let fileType = $state('1 Firmware Upgrade Image');
	let source = $state<'stored' | 'external'>('stored');
	let fileId = $state('');
	let files = $state<StoredFile[]>([]);
	let command = $state('');
	let test = $state('ip_ping');
	let diagTarget = $state('');
	let diagCount = $state('');
	let args = $state<Record<string, string>>({});
	let commands = $state<(SupportedCommand & { path: string })[]>([]);
	let modelLoaded = $state(false);

	$effect(() => {
		if (kind === 'operate' && !modelLoaded) {
			modelLoaded = true;
			api
				.supportedModel(deviceId)
				.then((sm) => {
					commands = sm.objects.flatMap((o) =>
						o.commands.map((c) => ({ ...c, path: o.path + c.name }))
					);
				})
				.catch(() => (commands = []));
		}
	});

	// Supported command matching the input ({i} = any instance number).
	const selected = $derived(
		commands.find(
			(c) =>
				new RegExp('^' + c.path.replace(/[.()]/g, '\\$&').replace(/\{i\}/g, '\\d+') + '$').test(
					command
				) || c.path === command
		)
	);
	let busy = $state(false);
	let error = $state('');

	$effect(() => {
		if (!path) path = `${root}.DeviceInfo.`;
	});

	$effect(() => {
		if (kind === 'download') {
			api
				.files()
				.then((f) => {
					files = f;
					if (!fileId && f.length > 0) fileId = f[0].id;
				})
				.catch(() => (files = []));
		}
	});

	function payload(): { kind: string; payload?: unknown } {
		switch (kind) {
			case 'get_parameter_values':
				return { kind, payload: { names: [path] } };
			case 'get_parameter_names':
				return { kind, payload: { path, next_level: true } };
			case 'set_parameter_values':
				return {
					kind,
					payload: { values: [secret ? { name, value, type, secret } : { name, value, type }] }
				};
			case 'add_object':
			case 'delete_object':
				return { kind, payload: { object: path } };
			case 'diagnostic': {
				const params: Record<string, string> = {};
				if (test === 'wifi_neighbors') return { kind, payload: { test, params } };
				params[test === 'download' || test === 'upload' ? 'url' : 'host'] = diagTarget;
				if (diagCount && test !== 'download' && test !== 'upload') {
					params[test === 'trace_route' ? 'tries' : 'count'] = diagCount;
				}
				return { kind, payload: { test, params } };
			}
			case 'operate': {
				const input = Object.fromEntries(
					(selected?.inputs ?? []).filter((a) => args[a]).map((a) => [a, args[a]])
				);
				return { kind, payload: { command, input } };
			}
			case 'download':
				return source === 'stored'
					? { kind, payload: { file_id: fileId } }
					: { kind, payload: { file_type: fileType, url } };
			default:
				return { kind };
		}
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (kind === 'factory_reset' && !confirm(m.tasks.confirmFactoryReset)) return;
		busy = true;
		error = '';
		try {
			const t = await api.createTask(deviceId, payload());
			oncreated(m.tasks.queued(t.connection_request ?? 'skipped'));
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	const input = 'w-full rounded border-slate-300 text-sm';
</script>

<form
	onsubmit={submit}
	class="grid grid-cols-1 gap-3 rounded-md border border-slate-200 bg-white p-4 md:grid-cols-6"
>
	<label class="text-sm md:col-span-2">
		<span class="mb-1 block text-slate-600">{m.tasks.kind}</span>
		<select bind:value={kind} class={input}>
			{#each kinds as k (k)}<option value={k}>{m.tasks.kinds[k]}</option>{/each}
		</select>
	</label>

	{#if kind === 'get_parameter_values' || kind === 'get_parameter_names'}
		<label class="text-sm md:col-span-4">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.path}</span>
			<input bind:value={path} required class="{input} font-mono" />
		</label>
	{:else if kind === 'add_object' || kind === 'delete_object'}
		<label class="text-sm md:col-span-4">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.object}</span>
			<input bind:value={path} required pattern=".*\.$" class="{input} font-mono" />
		</label>
	{:else if kind === 'set_parameter_values'}
		<label class="text-sm md:col-span-2">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.name}</span>
			<input bind:value={name} required class="{input} font-mono" />
		</label>
		<label class="text-sm">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.value}</span>
			<input bind:value type={secret ? 'password' : 'text'} autocomplete="off" class={input} />
			<span
				class="mt-1 flex items-center gap-1 text-xs text-slate-600"
				title={m.tasks.fields.secretHint}
			>
				<input type="checkbox" bind:checked={secret} />
				{m.tasks.fields.secret}
			</span>
		</label>
		<label class="text-sm">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.type}</span>
			<select bind:value={type} class={input}>
				{#each ['string', 'boolean', 'unsignedInt', 'int', 'unsignedLong', 'long', 'dateTime', 'base64', 'hexBinary'] as t (t)}
					<option>{t}</option>
				{/each}
			</select>
		</label>
	{:else if kind === 'diagnostic'}
		<label class="text-sm">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.test}</span>
			<select bind:value={test} class={input}>
				{#each Object.keys(m.tasks.fields.tests) as t (t)}<option value={t}
						>{m.tasks.fields.tests[t]}</option
					>{/each}
			</select>
		</label>
		{#if test !== 'wifi_neighbors'}
			<label class="text-sm md:col-span-2">
				<span class="mb-1 block text-slate-600">{m.tasks.fields.target}</span>
				<input bind:value={diagTarget} required class="{input} font-mono" />
			</label>
		{/if}
		{#if test !== 'download' && test !== 'upload' && test !== 'wifi_neighbors'}
			<label class="text-sm">
				<span class="mb-1 block text-slate-600">{m.tasks.fields.count}</span>
				<input bind:value={diagCount} type="number" min="1" class={input} />
			</label>
		{/if}
	{:else if kind === 'operate'}
		<label class="text-sm md:col-span-4">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.command}</span>
			<input
				bind:value={command}
				required
				pattern=".*\(\)$"
				list="usp-commands"
				class="{input} font-mono"
			/>
			<datalist id="usp-commands">
				{#each commands as c (c.path)}<option value={c.path}>{c.type}</option>{/each}
			</datalist>
			<span class="mt-1 block text-xs text-slate-500"
				>{commands.length === 0
					? m.tasks.fields.noModel
					: command.includes('{i}')
						? m.tasks.fields.commandHint
						: selected?.type === 'async'
							? m.tasks.fields.async
							: ''}</span
			>
		</label>
		{#if selected && selected.inputs.length > 0}
			<fieldset class="grid min-w-0 grid-cols-1 gap-3 md:col-span-6 md:grid-cols-3">
				<legend class="mb-1 text-sm text-slate-600">{m.tasks.fields.inputs}</legend>
				{#each selected.inputs as a (a)}
					<label class="text-sm">
						<span class="mb-1 block font-mono text-xs text-slate-600">{a}</span>
						<input bind:value={args[a]} class={input} />
					</label>
				{/each}
			</fieldset>
		{/if}
	{:else if kind === 'download'}
		<label class="text-sm">
			<span class="mb-1 block text-slate-600">{m.tasks.fields.source}</span>
			<select bind:value={source} class={input}>
				<option value="stored">{m.tasks.fields.stored}</option>
				<option value="external">{m.tasks.fields.external}</option>
			</select>
		</label>
		{#if source === 'stored'}
			<label class="text-sm md:col-span-3">
				<span class="mb-1 block text-slate-600">{m.tasks.fields.file}</span>
				{#if files.length === 0}
					<p class="py-2 text-slate-500">{m.tasks.fields.noFiles}</p>
				{:else}
					<select bind:value={fileId} required class={input}>
						{#each files as f (f.id)}
							<option value={f.id}
								>{f.name}{f.version ? ` (${f.version})` : ''} · {bytes(f.size_bytes)}</option
							>
						{/each}
					</select>
				{/if}
			</label>
		{:else}
			<label class="text-sm md:col-span-2">
				<span class="mb-1 block text-slate-600">{m.tasks.fields.url}</span>
				<input bind:value={url} required type="url" class="{input} font-mono" />
			</label>
			<label class="text-sm">
				<span class="mb-1 block text-slate-600">{m.tasks.fields.fileType}</span>
				<input bind:value={fileType} class={input} />
			</label>
		{/if}
	{/if}

	<div class="flex flex-wrap items-end gap-y-2 md:col-span-6">
		<button
			disabled={busy}
			class="rounded bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-800 disabled:opacity-50"
			>{m.tasks.submit}</button
		>
		{#if error}<p class="ml-3 min-w-0 text-sm break-words text-red-700">{error}</p>{/if}
	</div>
</form>
