<script lang="ts">
	import type { SeriesPoint } from '$lib/api';

	let {
		points,
		format,
		domain
	}: {
		points: SeriesPoint[];
		/** Axis value format; default plain numbers. */
		format?: (v: number) => string;
		/** Fixed value axis, e.g. [0, 1]; default = range of the points. */
		domain?: [number, number];
	} = $props();

	const W = 800;
	const H = 220;
	const PAD = { l: 56, r: 12, t: 10, b: 24 };

	const geo = $derived.by(() => {
		if (points.length === 0) return null;
		const xs = points.map((p) => new Date(p.ts).getTime());
		const x0 = xs[0];
		const x1 = Math.max(xs[xs.length - 1], x0 + 1);
		let y0 = domain ? domain[0] : Math.min(...points.map((p) => p.min));
		let y1 = domain ? domain[1] : Math.max(...points.map((p) => p.max));
		if (y0 === y1) {
			y0 -= 1;
			y1 += 1;
		}
		const x = (t: number) => PAD.l + ((t - x0) / (x1 - x0)) * (W - PAD.l - PAD.r);
		const y = (v: number) => PAD.t + (1 - (v - y0) / (y1 - y0)) * (H - PAD.t - PAD.b);
		const line = points.map((p, i) => `${x(xs[i])},${y(p.avg)}`).join(' ');
		const band =
			points.map((p, i) => `${x(xs[i])},${y(p.max)}`).join(' ') +
			' ' +
			[...points]
				.reverse()
				.map((p, i) => `${x(xs[xs.length - 1 - i])},${y(p.min)}`)
				.join(' ');
		const ticks = [y0, (y0 + y1) / 2, y1].map((v) => ({ v, y: y(v) }));
		return { line, band, ticks, x0, x1 };
	});

	const plain = (v: number) =>
		Math.abs(v) >= 1e6 ? v.toExponential(2) : Number.isInteger(v) ? String(v) : v.toFixed(2);
	const fmt = $derived(format ?? plain);
	const when = (t: number) =>
		new Date(t).toLocaleString(undefined, {
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
</script>

{#if geo}
	<!-- Phones draw the chart much smaller -> labels larger in chart units. -->
	<svg viewBox="0 0 {W} {H}" class="h-auto w-full overflow-visible md:overflow-hidden" role="img">
		{#each geo.ticks as t (t.v)}
			<line x1={PAD.l} x2={W - PAD.r} y1={t.y} y2={t.y} class="stroke-slate-200" />
			<text
				x={PAD.l - 6}
				y={t.y + 4}
				text-anchor="end"
				class="fill-slate-500 text-[22px] md:text-[11px]">{fmt(t.v)}</text
			>
		{/each}
		<polygon points={geo.band} class="fill-teal-100" />
		<polyline points={geo.line} fill="none" class="stroke-teal-700" stroke-width="1.5" />
		<text x={PAD.l} y={H - 6} class="fill-slate-500 text-[22px] md:text-[11px]">{when(geo.x0)}</text
		>
		<text
			x={W - PAD.r}
			y={H - 6}
			text-anchor="end"
			class="fill-slate-500 text-[22px] md:text-[11px]">{when(geo.x1)}</text
		>
	</svg>
{/if}
