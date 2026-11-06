<script lang="ts">
	import { api, ago, bytes, type StoredFile } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';

	// Change shared files -> account without device scope only.
	const canChange = $derived(!session.me?.scope);

	let files = $state<StoredFile[] | null>(null);
	let error = $state<unknown>(null);
	let chosen = $state<FileList | null>(null);
	let fileType = $state('1 Firmware Upgrade Image');
	let version = $state('');
	let busy = $state(false);
	let notice = $state('');

	async function load() {
		error = null;
		try {
			files = await api.files();
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});

	async function upload(e: SubmitEvent) {
		e.preventDefault();
		const f = chosen?.[0];
		if (!f) return;
		busy = true;
		notice = '';
		try {
			await api.uploadFile(f, fileType, version);
			version = '';
			await load();
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function remove(f: StoredFile) {
		if (!confirm(m.files.confirmDelete(f.name))) return;
		try {
			await api.deleteFile(f.id);
			await load();
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	const input = 'w-full rounded border-slate-300 text-sm';
</script>

<h1 class="text-xl font-semibold">{m.files.title}</h1>
<p class="mt-1 text-sm text-slate-600">{m.files.intro}</p>

{#if canChange}<form
		onsubmit={upload}
		class="mt-4 grid gap-3 rounded-md border border-slate-200 bg-white p-4 md:grid-cols-6"
	>
		<label class="text-sm md:col-span-2">
			<span class="mb-1 block text-slate-600">{m.files.choose}</span>
			<input type="file" bind:files={chosen} required class="block w-full text-sm" />
		</label>
		<label class="text-sm md:col-span-2">
			<span class="mb-1 block text-slate-600">{m.files.fileType}</span>
			<select bind:value={fileType} class={input}>
				<option>1 Firmware Upgrade Image</option>
				<option>3 Vendor Configuration File</option>
				<option>2 Web Content</option>
			</select>
		</label>
		<label class="text-sm">
			<span class="mb-1 block text-slate-600">{m.files.version}</span>
			<input bind:value={version} class={input} />
		</label>
		<div class="flex items-end">
			<button
				disabled={busy}
				class="w-full rounded bg-teal-700 px-4 py-2.5 text-sm text-white hover:bg-teal-800 disabled:opacity-50 md:w-auto md:py-2"
				>{busy ? m.files.uploading : m.files.upload}</button
			>
		</div>
	</form>{/if}
{#if notice}<p class="mt-3 text-sm text-red-700">{notice}</p>{/if}

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if files === null}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else if files.length === 0}
	<p class="mt-4 text-slate-500">{m.files.empty}</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					<th class="px-3 py-2">{m.files.name}</th>
					<th class="px-3 py-2">{m.files.fileType}</th>
					<th class="px-3 py-2">{m.files.versionColumn}</th>
					<th class="px-3 py-2">{m.files.size}</th>
					<th class="px-3 py-2">{m.files.sha256}</th>
					<th class="px-3 py-2">{m.files.uploaded}</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each files as f (f.id)}
					<tr class="border-t border-slate-100">
						<td class="px-3 py-2 font-mono font-medium md:font-normal">{f.name}</td>
						<td class="px-3 py-2" data-label={m.files.fileType}>{f.file_type}</td>
						<td class="px-3 py-2" data-label={m.files.versionColumn}
							>{f.version ?? m.common.none}</td
						>
						<td class="px-3 py-2" data-label={m.files.size}>{bytes(f.size_bytes)}</td>
						<td class="px-3 py-2 font-mono text-xs" data-label={m.files.sha256} title={f.sha256}
							>{f.sha256.slice(0, 16)}…</td
						>
						<td class="px-3 py-2 text-slate-500" data-label={m.files.uploaded} title={f.created_at}
							>{ago(f.created_at)}</td
						>
						<td class="px-3 py-2"
							>{#if canChange}<button
									onclick={() => remove(f)}
									class="text-xs text-red-700 hover:underline">{m.files.delete}</button
								>{/if}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
