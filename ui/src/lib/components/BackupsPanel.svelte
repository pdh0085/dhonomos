<script lang="ts">
	import { api, ago, bytes, type BackupDiff, type ConfigBackup, type StoredFile } from '$lib/api';
	import { m } from '$lib/messages';

	let { deviceId }: { deviceId: string } = $props();
	let backups = $state<ConfigBackup[]>([]);
	let files = $state<StoredFile[]>([]);
	let logs = $state<StoredFile[]>([]);
	let label = $state('');
	let notice = $state('');
	let diffOf = $state('');
	let drift = $state<BackupDiff | null>(null);

	const err = (e: unknown) => (notice = e instanceof Error ? e.message : String(e));

	async function load() {
		try {
			backups = await api.backups(deviceId);
			files = await api.configFiles(deviceId);
			logs = await api.logFiles(deviceId);
		} catch (e) {
			err(e);
		}
	}

	$effect(() => {
		load();
	});

	async function create(e: SubmitEvent) {
		e.preventDefault();
		try {
			const b = await api.createBackup(deviceId, label);
			notice = m.backups.created(b.count, b.notes.skipped_secrets ?? 0);
			label = '';
			await load();
		} catch (e) {
			err(e);
		}
	}

	async function compare(id: string) {
		diffOf = id;
		drift = null;
		try {
			drift = await api.backupDiff(id);
		} catch (e) {
			err(e);
		}
	}

	async function restore(id: string) {
		if (!confirm(m.backups.confirmRestore)) return;
		try {
			notice = m.backups.restored((await api.restoreBackup(id)).tasks.length);
		} catch (e) {
			err(e);
		}
	}

	async function requestFile() {
		try {
			notice = m.backups.requested((await api.requestConfigFile(deviceId)).connection_request);
		} catch (e) {
			err(e);
		}
	}

	async function requestLog() {
		try {
			notice = m.backups.requested((await api.requestLogFile(deviceId)).connection_request);
		} catch (e) {
			err(e);
		}
	}

	async function save(f: StoredFile) {
		try {
			await api.saveFile(f);
		} catch (e) {
			err(e);
		}
	}

	async function restoreFile(fileId: string) {
		if (!confirm(m.backups.confirmRestoreFile)) return;
		try {
			const t = await api.createTask(deviceId, { kind: 'download', payload: { file_id: fileId } });
			notice = m.tasks.queued(t.connection_request ?? 'skipped');
		} catch (e) {
			err(e);
		}
	}

	async function remove(id: string) {
		try {
			await api.deleteBackup(id);
			if (diffOf === id) drift = null;
			await load();
		} catch (e) {
			err(e);
		}
	}
</script>

<p class="mt-3 text-sm text-slate-600">{m.backups.intro}</p>
<form onsubmit={create} class="mt-3 flex flex-wrap items-end gap-3">
	<label class="w-full text-sm md:w-auto">
		<span class="mb-1 block text-slate-600">{m.backups.label}</span>
		<input bind:value={label} class="w-full rounded border-slate-300 text-sm md:w-64" />
	</label>
	<button class="rounded bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-800"
		>{m.backups.create}</button
	>
</form>
{#if notice}<p class="mt-3 rounded bg-slate-100 px-3 py-2 text-sm">{notice}</p>{/if}

{#if backups.length === 0}
	<p class="mt-3 text-slate-500">{m.backups.empty}</p>
{:else}
	<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<tbody>
				{#each backups as b (b.id)}
					<tr class="border-t border-slate-100 first:border-t-0">
						<td class="px-3 py-2">{b.label || '—'}</td>
						<td class="px-3 py-2 text-slate-500">{b.count} {m.backups.values.toLowerCase()}</td>
						<td class="px-3 py-2 text-slate-500" title={b.created_at}>{ago(b.created_at)}</td>
						<td class="px-3 py-2 text-right whitespace-nowrap">
							<button onclick={() => compare(b.id)} class="text-xs text-teal-800 hover:underline"
								>{m.backups.compare}</button
							>
							<button
								onclick={() => restore(b.id)}
								class="ml-3 text-xs text-teal-800 hover:underline">{m.backups.restore}</button
							>
							<button onclick={() => remove(b.id)} class="ml-3 text-xs text-red-700 hover:underline"
								>{m.device.delete}</button
							>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if drift}
	<div class="mt-4 rounded-md border border-slate-200 bg-white p-4 text-sm">
		{#if drift.changed.length === 0 && drift.missing.length === 0}
			<p>{m.backups.inSync(drift.unchanged)}</p>
		{:else}
			{#if drift.changed.length > 0}
				<h3 class="font-medium">{m.backups.changed}</h3>
				<table class="stack mt-2 min-w-full">
					<thead class="text-left text-slate-500"
						><tr
							><th class="py-1 pr-4">{m.params.path}</th><th class="py-1 pr-4"
								>{m.backups.backupValue}</th
							><th class="py-1">{m.backups.currentValue}</th></tr
						></thead
					>
					<tbody>
						{#each drift.changed as c (c.path)}
							<tr class="border-t border-slate-100">
								<td class="py-1 pr-4 font-mono text-xs">{c.path}</td>
								<td class="py-1 pr-4 font-mono text-xs" data-label={m.backups.backupValue}>
									{c.backup}
								</td>
								<td class="py-1 font-mono text-xs" data-label={m.backups.currentValue}>
									{c.current ?? m.common.none}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
			{#if drift.missing.length > 0}
				<h3 class="mt-3 font-medium">{m.backups.missing}</h3>
				<ul class="mt-1 font-mono text-xs break-all md:break-normal">
					{#each drift.missing as p (p)}<li>{p}</li>{/each}
				</ul>
			{/if}
		{/if}
	</div>
{/if}

<h2 class="mt-6 text-sm font-medium text-slate-700">{m.backups.files}</h2>
<p class="text-sm text-slate-600">{m.backups.filesIntro}</p>
<button
	onclick={requestFile}
	class="mt-2 rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
	>{m.backups.requestFile}</button
>
{#if files.length === 0}
	<p class="mt-2 text-sm text-slate-500">{m.backups.noFiles}</p>
{:else}
	<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<tbody>
				{#each files as f (f.id)}
					<tr class="border-t border-slate-100 first:border-t-0">
						<td class="px-3 py-2 font-mono text-xs">{f.name}</td>
						<td class="px-3 py-2 text-slate-500">{bytes(f.size_bytes)}</td>
						<td class="px-3 py-2 text-slate-500">{ago(f.created_at)}</td>
						<td class="px-3 py-2 text-right whitespace-nowrap"
							><button onclick={() => save(f)} class="text-xs text-teal-800 hover:underline"
								>{m.backups.saveFile}</button
							><button
								onclick={() => restoreFile(f.id)}
								class="ml-3 text-xs text-teal-800 hover:underline">{m.backups.restoreFile}</button
							></td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<h2 class="mt-6 text-sm font-medium text-slate-700">{m.backups.logs}</h2>
<p class="text-sm text-slate-600">{m.backups.logsIntro}</p>
<button
	onclick={requestLog}
	class="mt-2 rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100"
	>{m.backups.requestLog}</button
>
{#if logs.length === 0}
	<p class="mt-2 text-sm text-slate-500">{m.backups.noLogs}</p>
{:else}
	<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<tbody>
				{#each logs as f (f.id)}
					<tr class="border-t border-slate-100 first:border-t-0">
						<td class="px-3 py-2 font-mono text-xs">{f.name}</td>
						<td class="px-3 py-2 text-slate-500">{bytes(f.size_bytes)}</td>
						<td class="px-3 py-2 text-slate-500">{ago(f.created_at)}</td>
						<td class="px-3 py-2 text-right"
							><button onclick={() => save(f)} class="text-xs text-teal-800 hover:underline"
								>{m.backups.saveFile}</button
							></td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
