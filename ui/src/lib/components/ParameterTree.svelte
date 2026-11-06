<script lang="ts">
	import { ago, api, type Parameter, type Task } from '$lib/api';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';
	import { isSecret, isWriteOnlySecret } from '$lib/secrets';

	let {
		deviceId,
		protocol,
		params,
		onchanged
	}: {
		deviceId: string;
		protocol: string;
		params: Parameter[];
		onchanged: () => void;
	} = $props();

	interface Node {
		name: string;
		/** Object path, ends with `.`. */
		path: string;
		children: Map<string, Node>;
		leaves: Parameter[];
		count: number;
	}

	let search = $state('');
	let expanded = $state<Set<string>>(new Set());
	// Unsent edits: path -> new value.
	let edits = $state<Record<string, string>>({});
	let editing = $state<string | null>(null);
	// Task of apply/refresh + its result.
	let job = $state<{ task: Task; what: 'apply' | 'refresh'; count: number } | null>(null);
	let errors = $state<Record<string, string>>({});
	let message = $state('');
	let failed = $state(false);

	const canEdit = $derived(session.me?.role !== 'viewer');

	/** Objects + values; with `q` -> only paths containing `q`. */
	function build(list: Parameter[], q: string): Node {
		const root: Node = { name: '', path: '', children: new Map(), leaves: [], count: 0 };
		const needle = q.trim().toLowerCase();
		for (const p of list) {
			if (needle && !p.path.toLowerCase().includes(needle)) continue;
			const parts = p.path.split('.');
			const leaf = parts.pop() ?? '';
			if (!leaf) continue; // object path -> no value
			let node = root;
			node.count++;
			let path = '';
			for (const part of parts) {
				path += `${part}.`;
				let child = node.children.get(part);
				if (!child) {
					child = { name: part, path, children: new Map(), leaves: [], count: 0 };
					node.children.set(part, child);
				}
				child.count++;
				node = child;
			}
			node.leaves.push(p);
		}
		return root;
	}

	const tree = $derived(build(params, search));
	// Search active -> all matches open.
	const isOpen = (path: string) => search.trim() !== '' || expanded.has(path);

	function toggle(path: string) {
		const next = new Set(expanded);
		if (next.has(path)) next.delete(path);
		else next.add(path);
		expanded = next;
	}

	function allPaths(n: Node, out: string[] = []): string[] {
		for (const c of n.children.values()) {
			out.push(c.path);
			allPaths(c, out);
		}
		return out;
	}

	// Numbered instances by number, rest by name.
	const order = (a: string, b: string) => {
		const [x, y] = [Number(a), Number(b)];
		return Number.isInteger(x) && Number.isInteger(y) ? x - y : a.localeCompare(b);
	};

	const pendingIn = (path: string) => Object.keys(edits).some((p) => p.startsWith(path));
	const pendingCount = $derived(Object.keys(edits).length);

	function setEdit(p: Parameter, value: string) {
		if (value === (p.value ?? '') && !isSecret(p.path)) {
			const { [p.path]: _, ...rest } = edits;
			edits = rest;
		} else {
			edits = { ...edits, [p.path]: value };
		}
	}

	/** `9003 Invalid arguments | Device.X: 9007 Invalid value` -> per-parameter errors. */
	function parseErrors(text: string): Record<string, string> {
		const out: Record<string, string> = {};
		for (const part of text.split(' | ').slice(1)) {
			const at = part.indexOf(': ');
			if (at > 0) out[part.slice(0, at)] = part.slice(at + 2);
		}
		return out;
	}

	async function follow(task: Task, what: 'apply' | 'refresh', count: number) {
		job = { task, what, count };
		failed = false;
		message = '';
		const done = ['succeeded', 'failed', 'cancelled', 'expired'];
		for (let i = 0; i < 300 && !done.includes(job.task.state); i++) {
			await new Promise((r) => setTimeout(r, 2000));
			try {
				job = { ...job, task: await api.task(task.id) };
			} catch {
				// keep polling
			}
		}
		const t = job.task;
		if (t.state === 'succeeded') {
			if (what === 'apply') {
				edits = {};
				editing = null;
				errors = {};
				message = m.params.applied(count);
			} else {
				message = m.params.refreshed;
			}
			onchanged();
		} else {
			failed = true;
			message = t.error ?? m.params.states[t.state] ?? t.state;
			if (what === 'apply') errors = parseErrors(t.error ?? '');
		}
		job = null;
	}

	async function apply() {
		const byPath = new Map(params.map((p) => [p.path, p]));
		const values = Object.entries(edits).map(([name, value]) => ({
			name,
			value,
			type: byPath.get(name)?.type ?? 'string',
			...(isSecret(name) ? { secret: true } : {})
		}));
		try {
			const task = await api.createTask(deviceId, {
				kind: 'set_parameter_values',
				payload: { values }
			});
			await follow(task, 'apply', values.length);
		} catch (e) {
			failed = true;
			message = e instanceof Error ? e.message : String(e);
		}
	}

	async function refresh(path: string) {
		try {
			// CWMP: GPN first (writability), then GPV (runs after it).
			if (protocol === 'cwmp') {
				await api.createTask(deviceId, {
					kind: 'get_parameter_names',
					payload: { path, next_level: false }
				});
			}
			const task = await api.createTask(deviceId, {
				kind: 'get_parameter_values',
				payload: { names: [path] }
			});
			await follow(task, 'refresh', 0);
		} catch (e) {
			failed = true;
			message = e instanceof Error ? e.message : String(e);
		}
	}

	// USP only: cached supported data model of Agent firmware may be wrong
	// (e.g. update with same software version) -> drop + read again.
	let refreshingModel = $state(false);
	async function refreshModel() {
		refreshingModel = true;
		failed = false;
		message = '';
		try {
			const r = await api.refreshDataModel(deviceId);
			message = m.params.modelRefresh[r.status] ?? r.status;
		} catch (e) {
			failed = true;
			message = e instanceof Error ? e.message : String(e);
		} finally {
			refreshingModel = false;
		}
	}

	const shown = (p: Parameter) =>
		isSecret(p.path) && p.value ? '••••••' : (p.value ?? m.common.none);
	const unknownWritability = $derived(params.some((p) => p.writable === null));
</script>

<div class="mt-3 flex flex-wrap items-center gap-3">
	<input
		bind:value={search}
		placeholder={m.params.search}
		class="w-full rounded border-slate-300 font-mono text-sm md:w-96"
	/>
	<span class="text-sm text-slate-500">{m.params.shown(tree.count, params.length)}</span>
	<button
		onclick={() => (expanded = new Set(allPaths(tree)))}
		class="text-sm text-teal-800 hover:underline">{m.params.expandAll}</button
	>
	<button onclick={() => (expanded = new Set())} class="text-sm text-teal-800 hover:underline"
		>{m.params.collapseAll}</button
	>
	{#if protocol === 'usp' && canEdit}
		<button
			onclick={refreshModel}
			disabled={refreshingModel}
			title={m.params.refreshModelHint}
			class="ml-auto rounded border border-slate-300 px-3 py-1 text-sm hover:bg-slate-100 disabled:opacity-40"
			>{m.params.refreshModel}</button
		>
	{/if}
</div>
{#if !canEdit}
	<p class="mt-2 text-xs text-slate-500">{m.params.readOnlyRole}</p>
{:else if unknownWritability && protocol === 'cwmp'}
	<p class="mt-2 text-xs text-slate-500">{m.params.notWritableYet}</p>
{/if}

{#if pendingCount > 0 || job || message}
	<div
		class="sticky top-0 z-10 mt-3 flex flex-wrap items-center gap-3 rounded-md border px-4 py-2 text-sm {failed
			? 'border-red-200 bg-red-50 text-red-900'
			: pendingCount > 0 || job
				? 'border-amber-200 bg-amber-50 text-amber-900'
				: 'border-teal-200 bg-teal-50 text-teal-900'}"
	>
		{#if job}
			<span>{m.params.states[job.task.state] ?? job.task.state}</span>
		{:else if message}
			<span class="break-all">{message}</span>
		{/if}
		{#if pendingCount > 0 && !job}
			<span class="font-medium">{m.params.pending(pendingCount)}</span>
			<button onclick={apply} class="rounded bg-teal-700 px-3 py-1 text-white hover:bg-teal-800"
				>{m.params.apply}</button
			>
			<button
				onclick={() => {
					edits = {};
					errors = {};
					message = '';
				}}
				class="text-teal-900 hover:underline">{m.params.discard}</button
			>
		{/if}
	</div>
{/if}

{#if tree.count === 0}
	<p class="mt-3 text-slate-500">{m.params.empty}</p>
{:else}
	<div class="mt-3 rounded-md border border-slate-200 bg-white py-1 text-sm">
		{@render object(tree, 0)}
	</div>
{/if}

{#snippet object(n: Node, depth: number)}
	{#each [...n.children.values()].sort((a, b) => order(a.name, b.name)) as c (c.path)}
		<!-- Phones indent less -> deep paths keep room for names. -->
		<div
			class="group flex items-center gap-2 px-2 py-1 pl-[var(--pl-sm)] hover:bg-slate-50 md:pl-[var(--pl)]"
			style="--pl: {depth * 1.25 + 0.5}rem; --pl-sm: {depth * 0.5 + 0.5}rem"
		>
			<button onclick={() => toggle(c.path)} class="flex items-center gap-1 text-left">
				<span class="w-3 text-slate-400">{isOpen(c.path) ? '▾' : '▸'}</span>
				<span class="font-mono {Number.isInteger(Number(c.name)) ? 'text-slate-500' : ''}"
					>{c.name}</span
				>
				<span class="text-xs text-slate-400">{c.count}</span>
				{#if pendingIn(c.path)}<span class="h-2 w-2 rounded-full bg-amber-500"></span>{/if}
			</button>
			{#if canEdit}
				<button
					onclick={() => refresh(c.path)}
					disabled={!!job}
					title={m.params.refreshHint}
					class="ml-auto py-1 text-xs text-teal-800 hover:underline disabled:opacity-40 md:hidden md:py-0 md:group-hover:inline"
					>{m.params.refresh}</button
				>
			{/if}
		</div>
		{#if isOpen(c.path)}
			{#each [...c.leaves].sort((a, b) => a.path.localeCompare(b.path)) as p (p.path)}
				{@const name = p.path.slice(c.path.length)}
				{@const changed = p.path in edits}
				<!-- Phones: name on own line, value below, then type, age, Edit. -->
				<div
					class="flex flex-wrap items-start gap-x-3 gap-y-0.5 border-l-2 px-2 py-1 pl-[var(--pl-sm)] md:flex-nowrap md:gap-3 md:pl-[var(--pl)] {changed
						? 'border-amber-400 bg-amber-50/60'
						: errors[p.path]
							? 'border-red-400 bg-red-50/60'
							: 'border-transparent'}"
					style="--pl: {(depth + 1) * 1.25 + 1.25}rem; --pl-sm: {(depth + 1) * 0.5 + 1.25}rem"
				>
					<!-- Name column shrinks with indent -> values line up. -->
					<span
						class="w-full shrink-0 font-mono break-all text-slate-700 md:w-[var(--name-w)]"
						style="--name-w: max(8rem, calc(26rem - {(depth + 1) * 1.25 + 1.25}rem))">{name}</span
					>
					<div class="min-w-0 flex-1 basis-full md:basis-0">
						{#if editing === p.path || changed}
							{#if p.type === 'boolean'}
								<select
									value={edits[p.path] ?? p.value ?? 'false'}
									onchange={(e) => setEdit(p, (e.target as HTMLSelectElement).value)}
									class="rounded border-slate-300 py-0.5 text-sm"
								>
									<option value="true">true</option>
									<option value="false">false</option>
								</select>
							{:else}
								<input
									type={isSecret(p.path)
										? 'password'
										: /int|long/i.test(p.type ?? '')
											? 'number'
											: 'text'}
									value={edits[p.path] ?? (isSecret(p.path) ? '' : (p.value ?? ''))}
									oninput={(e) => setEdit(p, (e.target as HTMLInputElement).value)}
									class="w-full max-w-md rounded border-slate-300 py-0.5 font-mono text-sm"
								/>
							{/if}
							{#if changed}<span class="ml-2 text-xs text-slate-500"
									>{isSecret(p.path) ? '' : `was ${p.value ?? '—'}`}</span
								>{/if}
						{:else if p.value === '' && isWriteOnlySecret(p.path)}
							<span class="text-slate-500 italic" title={m.params.hiddenByDeviceHint}
								>{m.params.hiddenByDevice}</span
							>
						{:else}
							<span class="font-mono break-all">{shown(p)}</span>
						{/if}
						{#if errors[p.path]}<div class="text-xs text-red-700">{errors[p.path]}</div>{/if}
					</div>
					<span class="w-24 shrink-0 text-xs text-slate-400">{p.type ?? ''}</span>
					<span class="w-20 shrink-0 text-xs text-slate-400" title={p.updated_at}
						>{ago(p.updated_at)}</span
					>
					<span class="w-12 shrink-0 text-right">
						<!-- Read-only -> no Edit. Unknown writability -> may try
						     (device refusal shows next to value). -->
						{#if canEdit && p.writable !== false && editing !== p.path && !changed}
							<button
								onclick={() => (editing = p.path)}
								title={p.writable === null ? m.params.unknownWritable : undefined}
								class="text-xs {p.writable ? 'text-teal-800' : 'text-slate-400'} hover:underline"
								>{m.params.edit}</button
							>
						{/if}
					</span>
				</div>
			{/each}
			{@render object(c, depth + 1)}
		{/if}
	{/each}
{/snippet}
