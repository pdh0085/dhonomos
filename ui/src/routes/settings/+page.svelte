<script lang="ts">
	import {
		api,
		ago,
		parseScope,
		scopeText,
		type ApiKeyInfo,
		type ServerSetting,
		type ServerSettingChange,
		type UserAccount
	} from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { m } from '$lib/messages';

	let users = $state<UserAccount[]>([]);
	let keys = $state<ApiKeyInfo[]>([]);
	let server = $state<ServerSetting[]>([]);
	let error = $state<unknown>(null);
	let notice = $state('');
	let newKey = $state('');
	let username = $state('');
	let password = $state('');
	let role = $state('operator');
	let keyName = $state('');
	let keyRole = $state('viewer');
	let scope = $state('');
	let keyScope = $state('');
	const roles = ['admin', 'operator', 'viewer'];

	async function load() {
		try {
			[users, keys, server] = await Promise.all([api.users(), api.apiKeys(), api.serverSettings()]);
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});

	const act = async (f: () => Promise<unknown>) => {
		notice = '';
		try {
			await f();
			await load();
		} catch (e) {
			notice = e instanceof Error ? e.message : String(e);
		}
	};

	async function addUser(e: SubmitEvent) {
		e.preventDefault();
		await act(async () => {
			await api.createUser(username, password, role, parseScope(scope));
			username = password = scope = '';
		});
	}

	async function addKey(e: SubmitEvent) {
		e.preventDefault();
		await act(async () => {
			newKey = (await api.createApiKey(keyName, keyRole, parseScope(keyScope))).key;
			keyName = keyScope = '';
		});
	}

	function editScope(u: UserAccount) {
		const text = prompt(m.settings.scopePrompt, scopeText(u.scope));
		if (text === null) return;
		act(() => api.updateUser(u.id, { scope: parseScope(text) }));
	}

	/** Server options by group; groups in order of first appearance. */
	const serverGroups = $derived.by(() => {
		const groups = new Map<string, ServerSetting[]>();
		for (const s of server) groups.set(s.group, [...(groups.get(s.group) ?? []), s]);
		return [...groups];
	});
	const sourceBadge: Record<string, string> = {
		cli: 'bg-teal-100 text-teal-900',
		env: 'bg-sky-100 text-sky-900',
		default: 'bg-slate-100 text-slate-700',
		unset: 'bg-slate-50 text-slate-400',
		web: 'bg-amber-100 text-amber-900'
	};

	// Inline editor of a runtime option: 1 at a time.
	let editing = $state<string | null>(null);
	let draft = $state('');
	let draftOn = $state(false);
	let editError = $state('');
	let saving = $state(false);

	function startEdit(s: ServerSetting) {
		editing = s.key;
		editError = '';
		// Shown value incl. masked parts -> must be typed again in full.
		draft = s.value ?? '';
		draftOn = s.value === 'true';
	}

	async function saveEdit(s: ServerSetting, change: () => Promise<unknown>) {
		saving = true;
		editError = '';
		try {
			await change();
			editing = null;
			server = await api.serverSettings();
		} catch (e) {
			editError = e instanceof Error ? e.message : String(e);
		} finally {
			saving = false;
		}
	}

	function save(s: ServerSetting) {
		const value =
			s.kind === 'bool'
				? draftOn
					? 'true'
					: 'false'
				: s.kind === 'list'
					? draft
							.split(',')
							.map((v) => v.trim())
							.filter((v) => v !== '')
					: draft;
		return saveEdit(s, () => api.setServerSetting(s.key, value));
	}

	// History of a runtime option, in a dialog.
	let historyOf = $state<ServerSetting | null>(null);
	let history = $state<ServerSettingChange[]>([]);
	let historyError = $state('');

	async function openHistory(s: ServerSetting) {
		historyOf = s;
		history = [];
		historyError = '';
		try {
			history = await api.serverSettingHistory(s.key);
		} catch (e) {
			historyError = e instanceof Error ? e.message : String(e);
		}
	}

	const shown = (v: string | string[] | null) =>
		v === null ? m.settings.historyNone : Array.isArray(v) ? v.join(', ') : v;

	const input = 'rounded border-slate-300 text-sm';
	const cell = 'px-3 py-2';
</script>

{#if error}
	<ErrorBox {error} onretry={load} />
{:else}
	<p class="text-sm text-slate-600">{m.settings.rolesHelp}</p>
	<p class="mt-1 text-sm text-slate-600">{m.settings.scopeHelp}</p>
	{#if notice}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm">{notice}</p>{/if}

	<h1 class="mt-4 text-xl font-semibold">{m.settings.users}</h1>
	<form onsubmit={addUser} class="mt-3 flex flex-wrap items-end gap-3">
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.username}</span><input
				bind:value={username}
				required
				class="{input} w-full md:w-auto"
			/></label
		>
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.password}</span><input
				bind:value={password}
				type="password"
				minlength="10"
				required
				class="{input} w-full md:w-auto"
			/></label
		>
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.role}</span><select
				bind:value={role}
				class="{input} w-full md:w-auto"
				>{#each roles as r (r)}<option value={r}>{m.settings.roles[r]}</option>{/each}</select
			></label
		>
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.scope}</span><input
				bind:value={scope}
				placeholder={m.settings.scopePlaceholder}
				disabled={role === 'admin'}
				class="{input} w-full disabled:bg-slate-100 md:w-72"
			/></label
		>
		<button class="rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2"
			>{m.settings.add}</button
		>
	</form>
	<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600"
				><tr
					><th class={cell}>{m.settings.username}</th><th class={cell}>{m.settings.role}</th><th
						class={cell}>{m.settings.scope}</th
					><th class={cell}>{m.settings.twoFactor}</th><th class={cell}>{m.settings.lastLogin}</th
					><th></th></tr
				></thead
			>
			<tbody>
				{#each users as u (u.id)}
					<tr class="border-t border-slate-100">
						<td class={cell}
							>{u.username}{#if u.disabled}<span class="ml-2 text-xs text-slate-500"
									>{m.settings.disabled}</span
								>{/if}</td
						>
						<td class={cell} data-label={m.settings.role}
							><select
								value={u.role}
								onchange={(e) =>
									act(() => api.updateUser(u.id, { role: (e.target as HTMLSelectElement).value }))}
								class={input}
								>{#each roles as r (r)}<option value={r}>{m.settings.roles[r]}</option
									>{/each}</select
							></td
						>
						<td class="{cell} {u.scope ? '' : 'text-slate-500'}" data-label={m.settings.scope}
							>{scopeText(u.scope) || m.settings.allDevices}</td
						>
						<td
							class="{cell} {u.totp_enabled ? '' : 'text-slate-500'}"
							data-label={m.settings.twoFactor}
							>{u.totp_enabled ? m.settings.twoFactorOn : m.settings.twoFactorOff}</td
						>
						<td class="{cell} text-slate-500" data-label={m.settings.lastLogin}
							>{ago(u.last_login_at, m.common.never)}</td
						>
						<td class="{cell} flex-wrap text-right md:whitespace-nowrap">
							{#if u.role !== 'admin'}<button
									onclick={() => editScope(u)}
									class="mr-3 py-2 text-xs text-teal-800 hover:underline md:py-0"
									>{m.settings.editScope}</button
								>{/if}
							<button
								onclick={() => act(() => api.updateUser(u.id, { disabled: !u.disabled }))}
								class="py-2 text-xs text-teal-800 hover:underline md:py-0"
								>{u.disabled ? m.settings.enable : m.settings.disable}</button
							>
							<button
								onclick={() => {
									const p = prompt(m.settings.newPasswordPrompt);
									if (p) act(() => api.updateUser(u.id, { password: p }));
								}}
								class="ml-3 py-2 text-xs text-teal-800 hover:underline md:py-0"
								>{m.settings.resetPassword}</button
							>
							{#if u.totp_enabled}<button
									onclick={() =>
										confirm(m.settings.confirmResetTwoFactor(u.username)) &&
										act(() => api.resetUserTotp(u.id))}
									class="ml-3 py-2 text-xs text-teal-800 hover:underline md:py-0"
									>{m.settings.resetTwoFactor}</button
								>{/if}
							<button
								onclick={() =>
									confirm(m.settings.confirmRemove(u.username)) && act(() => api.deleteUser(u.id))}
								class="ml-3 py-2 text-xs text-red-700 hover:underline md:py-0"
								>{m.settings.remove}</button
							>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<h1 class="mt-8 text-xl font-semibold">{m.settings.keys}</h1>
	<form onsubmit={addKey} class="mt-3 flex flex-wrap items-end gap-3">
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.keyName}</span><input
				bind:value={keyName}
				required
				class="{input} w-full md:w-auto"
			/></label
		>
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.role}</span><select
				bind:value={keyRole}
				class="{input} w-full md:w-auto"
				>{#each roles as r (r)}<option value={r}>{m.settings.roles[r]}</option>{/each}</select
			></label
		>
		<label class="w-full text-sm md:w-auto"
			><span class="mb-1 block text-slate-600">{m.settings.scope}</span><input
				bind:value={keyScope}
				placeholder={m.settings.scopePlaceholder}
				disabled={keyRole === 'admin'}
				class="{input} w-full disabled:bg-slate-100 md:w-72"
			/></label
		>
		<button class="rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 md:py-2"
			>{m.settings.createKey}</button
		>
	</form>
	{#if newKey}
		<p class="mt-3 rounded bg-amber-50 px-3 py-2 text-sm text-amber-900">
			{m.settings.keyShown} <code class="font-mono break-all">{newKey}</code>
		</p>
	{/if}
	<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600"
				><tr
					><th class={cell}>{m.settings.keyName}</th><th class={cell}>{m.settings.prefix}</th><th
						class={cell}>{m.settings.role}</th
					><th class={cell}>{m.settings.scope}</th><th class={cell}>{m.settings.lastUsed}</th><th
					></th></tr
				></thead
			>
			<tbody>
				{#each keys as k (k.id)}
					<tr class="border-t border-slate-100 {k.revoked_at ? 'text-slate-400' : ''}">
						<td class={cell}>{k.name}</td>
						<td class="{cell} font-mono" data-label={m.settings.prefix}>{k.prefix}…</td>
						<td class={cell} data-label={m.settings.role}>{m.settings.roles[k.role] ?? k.role}</td>
						<td class="{cell} {k.scope ? '' : 'text-slate-500'}" data-label={m.settings.scope}
							>{scopeText(k.scope) || m.settings.allDevices}</td
						>
						<td class={cell} data-label={m.settings.lastUsed}
							>{ago(k.last_used_at, m.common.never)}</td
						>
						<td class="{cell} text-right"
							>{#if k.revoked_at}{m.settings.revoked}{:else}<button
									onclick={() => act(() => api.revokeApiKey(k.id))}
									class="py-2 text-xs text-red-700 hover:underline md:py-0"
									>{m.settings.revoke}</button
								>{/if}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<h1 class="mt-8 text-xl font-semibold">{m.settings.server}</h1>
	<p class="mt-1 text-sm text-slate-600">{m.settings.serverIntro}</p>
	<div class="mt-3 space-y-2">
		{#each serverGroups as [group, items] (group)}
			<details class="rounded-md border border-slate-200 bg-white">
				<summary class="cursor-pointer px-3 py-2 text-sm font-medium"
					>{m.settings.groups[group] ?? group}
					<span class="ml-1 text-xs font-normal text-slate-500">({items.length})</span></summary
				>
				<div class="overflow-x-auto border-t border-slate-100">
					<table class="stack min-w-full text-sm">
						<thead class="bg-slate-100 text-left text-slate-600"
							><tr
								><th class={cell}>{m.settings.option}</th><th class={cell}>{m.settings.value}</th
								><th class={cell}>{m.settings.source}</th><th class={cell}>{m.settings.category}</th
								><th></th></tr
							></thead
						>
						<tbody>
							{#each items as s (s.key)}
								<tr class="border-t border-slate-100 align-top">
									<td class={cell} title={s.help}
										><div class="min-w-0">
											<code class="font-mono">{s.flag}</code>
											<div class="font-mono text-xs text-slate-500">{s.env}</div>
											<div class="mt-0.5 max-w-md text-xs text-slate-500">{s.help}</div>
										</div></td
									>
									<td class="{cell} font-mono break-all" data-label={m.settings.value}>
										<div class="min-w-0 flex-1">
											{#if editing === s.key}
												<form
													class="font-sans"
													onsubmit={(e) => {
														e.preventDefault();
														save(s);
													}}
												>
													{#if s.kind === 'bool'}
														<label class="flex items-center gap-2"
															><input type="checkbox" bind:checked={draftOn} class="rounded" />
															<code class="font-mono">{draftOn ? 'true' : 'false'}</code></label
														>
													{:else}
														<input bind:value={draft} class="{input} w-full font-mono md:w-80" />
														{#if s.kind === 'list'}<div class="mt-1 text-xs text-slate-500">
																{m.settings.listHelp}
															</div>{/if}
														{#if draft.includes('****')}<div class="mt-1 text-xs text-slate-500">
																{m.settings.maskedHelp}
															</div>{/if}
													{/if}
													<div class="mt-2 flex flex-wrap gap-2">
														<button
															disabled={saving}
															class="rounded bg-teal-700 px-3 py-2 text-xs text-white hover:bg-teal-800 disabled:opacity-50 md:py-1"
															>{m.settings.save}</button
														>
														<button
															type="button"
															onclick={() => (editing = null)}
															class="rounded border border-slate-300 px-3 py-2 text-xs hover:bg-slate-50 md:py-1"
															>{m.settings.cancel}</button
														>
														{#if s.web_value !== null}<button
																type="button"
																disabled={saving}
																onclick={() => saveEdit(s, () => api.resetServerSetting(s.key))}
																class="rounded border border-slate-300 px-3 py-2 text-xs hover:bg-slate-50 disabled:opacity-50 md:py-1"
																>{m.settings.resetDefault}</button
															>{/if}
													</div>
													{#if editError}<p class="mt-2 text-xs text-red-700">{editError}</p>{/if}
												</form>
											{:else if s.category === 'secret'}<span class="font-sans text-slate-500"
													>{s.is_set ? m.settings.secretSet : m.settings.secretNotSet}</span
												>{:else if s.value === null}<span class="text-slate-400">—</span
												>{:else}{s.value}{/if}
											{#if s.locked_reason}
												<div class="mt-1 font-sans text-xs text-slate-500">
													{m.settings.locked(s.locked_reason)}
												</div>
												{#if s.web_value !== null}<div
														class="mt-0.5 font-sans text-xs text-amber-800"
													>
														{m.settings.webIgnored}:
														<code class="font-mono">{shown(s.web_value)}</code>
													</div>{/if}
											{/if}
										</div>
									</td>
									<td class={cell} data-label={m.settings.source}
										><span class="rounded px-2 py-0.5 text-xs {sourceBadge[s.source] ?? ''}"
											>{m.settings.sources[s.source] ?? s.source}</span
										></td
									>
									<td
										class="{cell} whitespace-nowrap text-slate-600"
										data-label={m.settings.category}
										>{m.settings.categories[s.category] ?? s.category}</td
									>
									<td class="{cell} text-right whitespace-nowrap">
										{#if s.editable && editing !== s.key}<button
												onclick={() => startEdit(s)}
												class="py-2 text-xs text-teal-800 hover:underline md:py-0"
												>{m.settings.edit}</button
											>{/if}
										{#if s.category === 'runtime'}<button
												onclick={() => openHistory(s)}
												class="ml-3 py-2 text-xs text-teal-800 hover:underline md:py-0"
												>{m.settings.history}</button
											>{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</details>
		{/each}
	</div>
{/if}

{#if historyOf}
	<Modal title={m.settings.historyTitle(historyOf.flag)} onclose={() => (historyOf = null)}>
		{#if historyError}
			<p class="text-red-700">{historyError}</p>
		{:else if history.length === 0}
			<p class="text-slate-500">{m.settings.historyEmpty}</p>
		{:else}
			<table class="stack min-w-full text-sm">
				<thead class="bg-slate-100 text-left text-slate-600"
					><tr
						><th class={cell}>{m.settings.when}</th><th class={cell}>{m.settings.who}</th><th
							class={cell}>{m.settings.before}</th
						><th class={cell}>{m.settings.after}</th></tr
					></thead
				>
				<tbody>
					{#each history as c, i (i)}
						<tr class="border-t border-slate-100 align-top">
							<td class="{cell} whitespace-nowrap" data-label={m.settings.when}
								>{new Date(c.at).toLocaleString()}</td
							>
							<td class={cell} data-label={m.settings.who}>{c.actor ?? m.settings.historyNone}</td>
							<td class="{cell} font-mono break-all" data-label={m.settings.before}
								>{shown(c.old)}</td
							>
							<td class="{cell} font-mono break-all" data-label={m.settings.after}
								>{#if c.new === null}<span class="font-sans text-slate-500"
										>{m.settings.historyReset}</span
									>{:else}{shown(c.new)}{/if}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</Modal>
{/if}
