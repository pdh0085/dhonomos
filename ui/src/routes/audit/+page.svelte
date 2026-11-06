<script lang="ts">
	import { api, ago, type AuditEntry } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';

	let entries = $state<AuditEntry[] | null>(null);
	let error = $state<unknown>(null);
	let actor = $state('');
	let action = $state('');
	let target = $state('');
	// Older page may exist.
	let more = $state(false);
	const PAGE = 100;

	const filters = () => ({ actor, action, target });

	async function load() {
		error = null;
		try {
			entries = await api.audit(filters());
			more = entries.length === PAGE;
		} catch (e) {
			error = e;
		}
	}

	async function loadMore() {
		if (!entries?.length) return;
		try {
			const older = await api.audit(filters(), entries[entries.length - 1].id);
			entries = [...entries, ...older];
			more = older.length === PAGE;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});
</script>

<h1 class="text-xl font-semibold">{m.audit.title}</h1>
<form
	onsubmit={(e) => {
		e.preventDefault();
		load();
	}}
	class="mt-3 flex flex-wrap items-end gap-2 text-sm"
>
	<input
		bind:value={actor}
		placeholder={m.audit.filterActor}
		class="w-full rounded border-slate-300 text-sm md:w-48"
	/>
	<input
		bind:value={action}
		placeholder={m.audit.filterAction}
		class="w-full rounded border-slate-300 font-mono text-sm md:w-64"
	/>
	<input
		bind:value={target}
		placeholder={m.audit.filterTarget}
		class="w-full rounded border-slate-300 font-mono text-sm md:w-80"
	/>
	<button
		class="rounded border border-slate-300 bg-white px-4 py-2.5 hover:bg-slate-100 md:px-3 md:py-1.5"
		>{m.audit.apply}</button
	>
</form>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if entries === null}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else if entries.length === 0}
	<p class="mt-4 text-slate-500">{m.audit.empty}</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					<th class="px-3 py-2">{m.audit.when}</th>
					<th class="px-3 py-2">{m.audit.actor}</th>
					<th class="px-3 py-2">{m.audit.action}</th>
					<th class="px-3 py-2">{m.audit.target}</th>
					<th class="px-3 py-2">{m.audit.detail}</th>
				</tr>
			</thead>
			<tbody>
				{#each entries as a (a.id)}
					<tr class="border-t border-slate-100 align-top">
						<td class="px-3 py-2 text-slate-500" data-label={m.audit.when} title={a.occurred_at}
							>{ago(a.occurred_at)}</td
						>
						<td class="px-3 py-2" data-label={m.audit.actor}>{a.actor}</td>
						<td class="px-3 py-2 font-mono" data-label={m.audit.action}>{a.action}</td>
						<td class="px-3 py-2" data-label={m.audit.target}>
							{#if a.target_type === 'device' && a.target_id}
								<a class="text-teal-800 hover:underline" href="/devices/{a.target_id}"
									>{a.target_type}</a
								>
							{:else}
								{a.target_type}
							{/if}
						</td>
						<td class="px-3 py-2 font-mono text-xs" data-label={m.audit.detail}
							>{JSON.stringify(a.detail)}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if more}
		<button
			onclick={loadMore}
			class="mt-3 rounded border border-slate-300 bg-white px-4 py-2.5 text-sm hover:bg-slate-100 md:px-3 md:py-1.5"
			>{m.audit.more}</button
		>
	{/if}
{/if}
