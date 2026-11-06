<script lang="ts">
	import { api, ago, download, type Alarm } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import AlarmRulesPanel from '$lib/components/AlarmRulesPanel.svelte';
	import SilencesPanel from '$lib/components/SilencesPanel.svelte';
	import { m } from '$lib/messages';

	let show = $state('active');
	let alarms = $state<Alarm[] | null>(null);
	let error = $state<unknown>(null);

	async function load() {
		try {
			alarms = (await api.alarms(show)).items;
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		void show;
		load();
		const timer = setInterval(load, 15000);
		return () => clearInterval(timer);
	});

	async function ack(id: string) {
		try {
			await api.ackAlarm(id);
			await load();
		} catch (e) {
			error = e;
		}
	}

	const severityColor: Record<string, string> = {
		critical: 'bg-red-600 text-white',
		major: 'bg-red-100 text-red-800',
		minor: 'bg-amber-100 text-amber-800',
		warning: 'bg-sky-100 text-sky-800'
	};
</script>

<div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between md:gap-4">
	<div>
		<h1 class="text-xl font-semibold">{m.alarms.title}</h1>
		<p class="text-sm text-slate-600">{m.alarms.intro}</p>
	</div>
	<div class="flex gap-2">
		<button
			onclick={() =>
				download(`/alarms/export.csv${show ? `?state=${show}` : ''}`, 'alarms.csv').catch(
					(e) => (error = e)
				)}
			class="rounded border border-slate-300 px-3 py-2.5 text-sm whitespace-nowrap hover:bg-slate-100 md:py-1.5"
			>{m.common.exportCsv}</button
		>
		<select bind:value={show} class="min-w-0 flex-1 rounded border-slate-300 text-sm md:flex-none">
			{#each ['active', 'cleared', ''] as s (s)}<option value={s}>{m.alarms.show[s]}</option>{/each}
		</select>
	</div>
</div>

{#if error}
	<div class="mt-4"><ErrorBox {error} onretry={load} /></div>
{:else if !alarms}
	<p class="mt-4 text-slate-500">{m.common.loading}</p>
{:else if alarms.length === 0}
	<p class="mt-4 text-slate-500">{m.alarms.empty}</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					<th class="px-3 py-2">{m.alarms.severity}</th>
					<th class="px-3 py-2">{m.alarms.device}</th>
					<th class="px-3 py-2">{m.alarms.rule}</th>
					<th class="px-3 py-2">{m.alarms.message}</th>
					<th class="px-3 py-2">{m.alarms.raised}</th>
					<th class="px-3 py-2">{m.alarms.state}</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each alarms as a (a.id)}
					<tr class="border-t border-slate-100">
						<td class="px-3 py-2" data-label={m.alarms.severity}
							><span class="rounded px-2 py-0.5 text-xs {severityColor[a.severity] ?? ''}"
								>{a.severity}</span
							></td
						>
						<td class="px-3 py-2 font-mono" data-label={m.alarms.device}
							><a href="/devices/{a.device_id}" class="text-teal-800 hover:underline"
								>{a.device ?? a.device_id}</a
							></td
						>
						<td class="px-3 py-2" data-label={m.alarms.rule}>{a.rule}</td>
						<td class="px-3 py-2" data-label={m.alarms.message}>{a.message}</td>
						<td class="px-3 py-2 text-slate-500" data-label={m.alarms.raised} title={a.raised_at}
							>{ago(a.raised_at)}</td
						>
						<td class="px-3 py-2" data-label={m.alarms.state}
							><div class="min-w-0">
								{a.state}{#if a.silenced_by}<span
										class="ml-1 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600"
										>{m.alarms.silenced}</span
									>{/if}{#if a.acked_by}<div class="text-xs text-slate-500">
										{m.alarms.acked(a.acked_by)}
									</div>{/if}
							</div></td
						>
						<td class="px-3 py-2 text-right">
							{#if a.state === 'active' && !a.acked_at}
								<button
									onclick={() => ack(a.id)}
									class="py-2 text-sm text-teal-800 hover:underline md:py-0 md:text-xs"
									>{m.alarms.ack}</button
								>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<AlarmRulesPanel />

<SilencesPanel />
