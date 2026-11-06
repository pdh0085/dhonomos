<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		ago,
		api,
		type DryRunItem,
		type Preset,
		type PresetRevision,
		type ScriptTrace as Trace
	} from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import ScriptTrace from '$lib/components/ScriptTrace.svelte';
	import { m } from '$lib/messages';

	const EVENTS = [
		'0 BOOTSTRAP',
		'1 BOOT',
		'2 PERIODIC',
		'4 VALUE CHANGE',
		'6 CONNECTION REQUEST',
		'USP CONNECT'
	];

	// Preset in edit. Not stored yet -> `revision` 0.
	const existing = page.url.searchParams.get('name');
	let name = $state(existing ?? '');
	let revision = $state(0);
	let enabled = $state(true);
	let priority = $state(0);
	let once = $state(false);
	let events = $state<string[]>([]);
	let otherEvents = $state('');
	let oui = $state('');
	let productClass = $state('');
	let version = $state('');
	let tags = $state('');
	let attributes = $state('');
	let deviceAge = $state<'any' | 'new' | 'known'>('any');
	let mode = $state<'tasks' | 'script'>('tasks');
	let tasks = $state('[\n  {"kind": "reboot"}\n]');
	let script = $state('pub fn main(device, args) {\n    \n}\n');
	let args = $state('');

	let loadError = $state<unknown>(null);
	let notice = $state('');
	let noticeOk = $state(false);
	let history = $state<PresetRevision[]>([]);

	let testDevice = $state('');
	let testEvents = $state<string[]>(['1 BOOT']);
	let testNew = $state(false);
	let testResult = $state<{ items: DryRunItem[]; scripts: Trace[] } | null>(null);
	let testError = $state<unknown>(null);

	const list = (text: string) =>
		text
			.split(',')
			.map((t) => t.trim())
			.filter(Boolean);

	function pairs(text: string, sep: RegExp): Record<string, string> {
		const out: Record<string, string> = {};
		for (const part of text.split(sep).map((p) => p.trim())) {
			if (!part) continue;
			const eq = part.indexOf('=');
			if (eq <= 0) throw new Error(m.presets.badPair(part));
			out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
		}
		return out;
	}

	const joinPairs = (o: Record<string, string> | undefined, sep: string) =>
		Object.entries(o ?? {})
			.map(([k, v]) => `${k}=${v}`)
			.join(sep);

	/** Form <- stored definition. */
	function fill(p: Preset) {
		enabled = p.enabled ?? true;
		priority = p.priority ?? 0;
		once = p.once ?? false;
		const w = p.when ?? {};
		events = (w.events ?? []).filter((e) => EVENTS.includes(e));
		otherEvents = (w.events ?? []).filter((e) => !EVENTS.includes(e)).join(', ');
		oui = w.oui ?? '';
		productClass = w.product_class ?? '';
		version = w.software_version ?? '';
		tags = (w.tags ?? []).join(', ');
		attributes = joinPairs(w.attributes, ', ');
		deviceAge = w.new_device === true ? 'new' : w.new_device === false ? 'known' : 'any';
		if (p.script_source !== undefined) {
			mode = 'script';
			script = p.script_source;
			args = joinPairs(p.args, '\n');
		} else {
			mode = 'tasks';
			tasks = JSON.stringify(p.run ?? [], null, 2);
		}
	}

	/** Preset as in the form. */
	function definition(): Partial<Preset> {
		const when: Preset['when'] = {};
		const ev = [...events, ...list(otherEvents)];
		if (ev.length) when.events = ev;
		if (oui.trim()) when.oui = oui.trim();
		if (productClass.trim()) when.product_class = productClass.trim();
		if (version.trim()) when.software_version = version.trim();
		if (list(tags).length) when.tags = list(tags);
		const attrs = pairs(attributes, /,/);
		if (Object.keys(attrs).length) when.attributes = attrs;
		if (deviceAge !== 'any') when.new_device = deviceAge === 'new';
		const p: Partial<Preset> = { name: name.trim(), enabled, priority, when };
		if (mode === 'script') {
			p.script_source = script;
			const a = pairs(args, /\n/);
			if (Object.keys(a).length) p.args = a;
		} else {
			try {
				p.run = JSON.parse(tasks);
			} catch (e) {
				throw new Error(m.presets.badJson(e instanceof Error ? e.message : String(e)));
			}
			p.once = once;
		}
		return p;
	}

	async function load() {
		if (!existing) return;
		try {
			const sp = await api.preset(existing);
			revision = sp.revision ?? 0;
			fill(sp.definition);
			history = await api.presetHistory(existing);
			loadError = null;
		} catch (e) {
			loadError = e;
		}
	}

	$effect(() => {
		load();
	});

	const report = (text: string, ok: boolean) => {
		notice = text;
		noticeOk = ok;
	};
	const failed = (e: unknown) => report(e instanceof Error ? e.message : String(e), false);

	async function check() {
		try {
			await api.validatePreset(definition());
			report(m.presets.valid, true);
		} catch (e) {
			failed(e);
		}
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		try {
			const sp = await api.savePreset(name.trim(), definition(), revision);
			revision = sp.revision ?? 0;
			report(m.presets.saved(revision), true);
			if (!existing) {
				await goto(`/presets/edit?name=${encodeURIComponent(sp.name)}`, { replaceState: true });
			}
			history = await api.presetHistory(sp.name);
		} catch (err) {
			failed(err);
		}
	}

	async function remove() {
		if (!existing || !confirm(m.presets.confirmRemove(existing))) return;
		try {
			await api.deletePreset(existing, revision);
			await goto('/presets');
		} catch (e) {
			failed(e);
		}
	}

	async function test(e: SubmitEvent) {
		e.preventDefault();
		try {
			testResult = await api.presetDryRun(testDevice.trim(), testEvents, testNew, {
				...definition(),
				name: name.trim() || 'draft'
			});
			testError = null;
		} catch (err) {
			testError = err;
			testResult = null;
		}
	}

	const input = 'mt-1 block w-full rounded border-slate-300 text-sm';
	const label = 'block text-sm';
	const hint = 'text-slate-600';
</script>

<a href="/presets" class="text-sm text-teal-800 hover:underline">← {m.presets.back}</a>
<h1 class="mt-2 text-xl font-semibold">
	{existing ? m.presets.editTitle(existing) : m.presets.newTitle}
</h1>

{#if loadError}
	<div class="mt-4"><ErrorBox error={loadError} onretry={load} /></div>
{:else}
	<form onsubmit={save} class="mt-4 space-y-4">
		<div class="grid gap-4 rounded-md border border-slate-200 bg-white p-4 md:grid-cols-4">
			<label class="{label} md:col-span-2">
				<span class={hint}>{m.presets.name}</span>
				<input
					bind:value={name}
					required
					maxlength="100"
					disabled={!!existing}
					class="{input} disabled:bg-slate-100"
				/>
				<span class="text-xs text-slate-500">{m.presets.nameHint}</span>
			</label>
			<label class={label}>
				<span class={hint}>{m.presets.priority}</span>
				<input type="number" bind:value={priority} min="-32768" max="32767" class={input} />
				<span class="text-xs text-slate-500">{m.presets.priorityHint}</span>
			</label>
			<label class="flex items-center gap-2 self-center text-sm"
				><input type="checkbox" bind:checked={enabled} />{m.presets.enabled}</label
			>
		</div>

		<fieldset class="rounded-md border border-slate-200 bg-white p-4">
			<legend class="px-1 font-medium">{m.presets.conditions}</legend>
			<p class="text-sm {hint}">{m.presets.conditionsHint}</p>
			<div class="mt-2 flex flex-wrap gap-3 text-sm">
				{#each EVENTS as ev (ev)}
					<label class="flex items-center gap-1"
						><input type="checkbox" value={ev} bind:group={events} />{ev}</label
					>
				{/each}
			</div>
			<div class="mt-3 grid gap-4 md:grid-cols-3">
				<label class={label}
					><span class={hint}>{m.presets.otherEvents}</span><input
						bind:value={otherEvents}
						placeholder="M Download"
						class={input}
					/></label
				>
				<label class={label}
					><span class={hint}>{m.presets.oui}</span><input bind:value={oui} class={input} /></label
				>
				<label class={label}
					><span class={hint}>{m.presets.productClass}</span><input
						bind:value={productClass}
						class={input}
					/></label
				>
				<label class={label}
					><span class={hint}>{m.presets.version}</span><input
						bind:value={version}
						placeholder="2\..*"
						class="{input} font-mono"
					/></label
				>
				<label class={label}
					><span class={hint}>{m.presets.tagsField}</span><input
						bind:value={tags}
						class={input}
					/></label
				>
				<label class={label}
					><span class={hint}>{m.presets.attributesField}</span><input
						bind:value={attributes}
						placeholder="plan=gold"
						class={input}
					/></label
				>
				<label class={label}
					><span class={hint}>{m.presets.deviceAge}</span><select
						bind:value={deviceAge}
						class={input}
					>
						<option value="any">{m.presets.anyDevice}</option>
						<option value="new">{m.presets.newOnly}</option>
						<option value="known">{m.presets.knownOnly}</option>
					</select></label
				>
			</div>
		</fieldset>

		<fieldset class="rounded-md border border-slate-200 bg-white p-4">
			<legend class="px-1 font-medium">{m.presets.action}</legend>
			<div class="flex gap-4 text-sm">
				<label class="flex items-center gap-1"
					><input type="radio" value="tasks" bind:group={mode} />{m.presets.tasksMode}</label
				>
				<label class="flex items-center gap-1"
					><input type="radio" value="script" bind:group={mode} />{m.presets.scriptMode}</label
				>
			</div>
			{#if mode === 'tasks'}
				<p class="mt-2 text-sm {hint}">{m.presets.tasksHint}</p>
				<textarea
					bind:value={tasks}
					rows="10"
					spellcheck="false"
					class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
				></textarea>
				<label class="mt-2 flex items-center gap-2 text-sm"
					><input type="checkbox" bind:checked={once} />{m.presets.onceLabel}</label
				>
			{:else}
				<p class="mt-2 text-sm {hint}">{m.presets.scriptHint}</p>
				<textarea
					bind:value={script}
					rows="18"
					spellcheck="false"
					class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
				></textarea>
				<label class="mt-3 {label}"
					><span class={hint}>{m.presets.argsField}</span><textarea
						bind:value={args}
						rows="3"
						spellcheck="false"
						class="{input} font-mono text-xs"
					></textarea></label
				>
			{/if}
		</fieldset>

		<div class="flex flex-wrap items-center gap-2 text-sm">
			<button class="rounded bg-teal-700 px-4 py-2.5 text-white hover:bg-teal-800 md:py-2"
				>{m.presets.save}</button
			>
			<button
				type="button"
				onclick={check}
				class="rounded border border-slate-300 px-4 py-2.5 hover:bg-slate-100 md:py-2"
				>{m.presets.validate}</button
			>
			{#if existing}
				<button
					type="button"
					onclick={remove}
					class="ml-auto rounded px-4 py-2.5 text-red-700 hover:bg-red-50 md:py-2"
					>{m.presets.remove}</button
				>
			{/if}
		</div>
		{#if notice}
			<p
				class="rounded px-3 py-2 text-sm {noticeOk
					? 'bg-teal-50 text-teal-900'
					: 'bg-red-50 text-red-800'}"
			>
				{notice}
			</p>
		{/if}
	</form>

	<h2 class="mt-8 text-lg font-semibold">{m.presets.test}</h2>
	<p class="text-sm text-slate-600">{m.presets.testIntro}</p>
	<form
		onsubmit={test}
		class="mt-3 flex flex-wrap items-end gap-4 rounded-md border border-slate-200 bg-white p-4 text-sm"
	>
		<label class="block w-full md:w-auto">
			<span class="text-slate-600">{m.presets.device}</span>
			<input
				bind:value={testDevice}
				required
				class="mt-1 block w-full rounded border-slate-300 font-mono text-sm md:w-80"
			/>
		</label>
		<fieldset>
			<legend class="text-slate-600">{m.presets.events}</legend>
			<div class="mt-1 flex flex-wrap gap-3">
				{#each EVENTS as ev (ev)}
					<label class="flex items-center gap-1"
						><input type="checkbox" value={ev} bind:group={testEvents} />{ev}</label
					>
				{/each}
			</div>
		</fieldset>
		<label class="flex items-center gap-1"
			><input type="checkbox" bind:checked={testNew} />{m.presets.newDevice}</label
		>
		<button class="rounded bg-teal-700 px-4 py-2.5 text-white hover:bg-teal-800 md:px-3 md:py-1.5"
			>{m.presets.run}</button
		>
	</form>
	{#if testError}
		<div class="mt-3"><ErrorBox error={testError} onretry={() => (testError = null)} /></div>
	{:else if testResult}
		{#if testResult.items.length === 0 && testResult.scripts.length === 0}
			<p class="mt-3 text-sm text-slate-500">{m.presets.noMatch}</p>
		{/if}
		{#if testResult.items.length}
			<ul class="mt-3 space-y-1 rounded-md border border-slate-200 bg-white p-3 text-sm">
				{#each testResult.items as it, i (i)}
					<li>
						<span class="font-medium">{it.kind}</span>
						<span class="ml-2 font-mono text-xs break-all md:break-normal"
							>{JSON.stringify(it.payload)}</span
						>
						{#if !it.would_queue}<span class="ml-2 text-xs text-slate-500"
								>{m.presets.alreadyRan}</span
							>{/if}
					</li>
				{/each}
			</ul>
		{/if}
		{#each testResult.scripts as t, i (i)}
			<div class="mt-3 rounded-md border border-slate-200 bg-white p-3">
				<ScriptTrace trace={t} />
			</div>
		{/each}
	{/if}

	{#if history.length}
		<h2 class="mt-8 text-lg font-semibold">{m.presets.history}</h2>
		<ul class="mt-2 divide-y divide-slate-100 rounded-md border border-slate-200 bg-white text-sm">
			{#each history as h (h.revision)}
				<li class="flex flex-wrap items-center gap-3 px-3 py-2">
					<span class="font-mono">#{h.revision}</span>
					<span class="text-slate-600">{h.changed_by ?? '?'}</span>
					<span class="text-slate-500" title={h.changed_at}>{ago(h.changed_at)}</span>
					{#if h.deleted}<span class="text-xs text-red-700">{m.presets.deleted}</span>{/if}
					{#if !h.enabled}<span class="text-xs text-slate-500">{m.presets.disabled}</span>{/if}
					{#if h.definition && h.revision !== revision}
						<button
							onclick={() => h.definition && fill(h.definition)}
							class="ml-auto py-2 text-xs text-teal-800 hover:underline md:py-0"
							>{m.presets.restore}</button
						>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
{/if}
