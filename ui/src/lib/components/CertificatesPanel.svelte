<script lang="ts">
	import { ago, api, ApiError, type AgentCertificate, type IssuedCertificate } from '$lib/api';
	import ErrorBox from '$lib/components/ErrorBox.svelte';
	import { m } from '$lib/messages';
	import { session } from '$lib/session.svelte';

	let { deviceId }: { deviceId: string } = $props();

	let certs = $state<AgentCertificate[] | null>(null);
	let error = $state<unknown>(null);
	let notice = $state('');
	let days = $state(1095);
	let csr = $state('');
	let issued = $state<IssuedCertificate | null>(null);
	let disabled = $state(false);
	const admin = $derived(session.me?.role === 'admin');

	async function load() {
		try {
			certs = await api.certificates(deviceId);
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});

	async function issue(e: SubmitEvent) {
		e.preventDefault();
		notice = '';
		try {
			issued = await api.issueCertificate(deviceId, days, csr.trim() || undefined);
			csr = '';
			await load();
		} catch (err) {
			if (err instanceof ApiError && err.status === 404) disabled = true;
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	async function revoke(c: AgentCertificate) {
		const reason = prompt(m.certs.reasonPrompt);
		if (reason === null) return;
		try {
			await api.revokeCertificate(deviceId, c.id, reason);
			await load();
		} catch (err) {
			notice = err instanceof Error ? err.message : String(err);
		}
	}

	function save(text: string, name: string) {
		const a = document.createElement('a');
		a.href = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
		a.download = name;
		a.click();
		URL.revokeObjectURL(a.href);
	}

	const badge: Record<string, string> = {
		valid: 'bg-teal-50 text-teal-800',
		expired: 'bg-slate-100 text-slate-600',
		revoked: 'bg-red-50 text-red-800'
	};
	const cell = 'px-3 py-2';
</script>

<p class="mt-3 text-sm text-slate-600">{m.certs.intro}</p>
{#if error}
	<div class="mt-3"><ErrorBox {error} onretry={load} /></div>
{:else if certs === null}
	<p class="mt-3 text-slate-500">{m.common.loading}</p>
{:else if certs.length === 0}
	<p class="mt-3 text-slate-500">{m.certs.empty}</p>
{:else}
	<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="stack min-w-full text-sm">
			<thead class="bg-slate-100 text-left text-slate-600">
				<tr>
					<th class={cell}>{m.certs.serial}</th>
					<th class={cell}>{m.certs.state}</th>
					<th class={cell}>{m.certs.expires}</th>
					<th class={cell}>{m.certs.issued}</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each certs as c (c.id)}
					<tr class="border-t border-slate-100 align-top">
						<td
							class="{cell} font-mono text-xs"
							title={`SHA-256 ${c.sha256}`}
							data-label={m.certs.serial}>{c.serial}</td
						>
						<td class={cell} data-label={m.certs.state}>
							<div class="min-w-0">
								<span class="rounded px-2 py-0.5 text-xs {badge[c.state]}"
									>{m.certs.states[c.state]}</span
								>
								{#if c.revoked_at}<div class="mt-1 text-xs text-slate-500">
										{m.certs.revokedBy(c.revoked_by ?? '?', c.revoke_reason)}
									</div>{/if}
							</div>
						</td>
						<td class={cell} title={c.not_after} data-label={m.certs.expires}
							>{new Date(c.not_after).toLocaleDateString()}</td
						>
						<td class="{cell} text-slate-500" title={c.issued_at} data-label={m.certs.issued}
							>{ago(c.issued_at)} · {c.issued_by ?? '?'}</td
						>
						<td class="{cell} text-right"
							>{#if admin && c.state === 'valid'}<button
									onclick={() => revoke(c)}
									class="text-xs text-red-700 hover:underline">{m.certs.revoke}</button
								>{/if}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if notice}<p class="mt-3 rounded bg-red-50 px-3 py-2 text-sm text-red-800">{notice}</p>{/if}

{#if issued}
	<div class="mt-4 rounded-md border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
		<p>{m.certs.issued_ok}</p>
		<div class="mt-2 flex flex-wrap gap-2">
			<button
				onclick={() => issued && save(issued.certificate, `${issued.serial}.crt.pem`)}
				class="rounded border border-amber-300 bg-white px-3 py-1.5 hover:bg-amber-100"
				>{m.certs.download('certificate')}</button
			>
			{#if issued.client_pem}<button
					onclick={() => issued?.client_pem && save(issued.client_pem, 'client.pem')}
					class="rounded border border-amber-300 bg-white px-3 py-1.5 font-medium hover:bg-amber-100"
					>{m.certs.download('client.pem')}</button
				>{/if}
			{#if issued.private_key}<button
					onclick={() =>
						issued?.private_key && save(issued.private_key, `${issued.serial}.key.pem`)}
					class="rounded border border-amber-300 bg-white px-3 py-1.5 hover:bg-amber-100"
					>{m.certs.download('private key')}</button
				>{/if}
			<button
				onclick={() => issued && save(issued.ca_certificate, 'usp-ca.pem')}
				class="rounded border border-amber-300 bg-white px-3 py-1.5 hover:bg-amber-100"
				>{m.certs.download('CA certificate')}</button
			>
		</div>
		{#if issued.client_pem}<p class="mt-2 text-xs">{m.certs.installHint}</p>{/if}
	</div>
{/if}

{#if disabled}
	<p class="mt-4 text-sm text-slate-500">{m.certs.disabled}</p>
{:else if admin}
	<form
		onsubmit={issue}
		class="mt-4 space-y-3 rounded-md border border-slate-200 bg-white p-4 text-sm"
	>
		<label class="block"
			><span class="text-slate-600">{m.certs.days}</span><input
				type="number"
				min="1"
				max="3650"
				bind:value={days}
				class="mt-1 block w-32 rounded border-slate-300 text-sm"
			/></label
		>
		<label class="block"
			><span class="text-slate-600">{m.certs.csr}</span><textarea
				bind:value={csr}
				rows="4"
				spellcheck="false"
				class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
			></textarea></label
		>
		<button class="rounded bg-teal-700 px-4 py-2 text-white hover:bg-teal-800"
			>{m.certs.issue}</button
		>
	</form>
{:else}
	<p class="mt-4 text-sm text-slate-500">{m.certs.adminOnly}</p>
{/if}
