import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	compilerOptions: { runes: true },
	kit: {
		// Single-page app: every route falls back to index.html (served by dhonomos).
		adapter: adapter({ fallback: 'index.html' }),
		// Absolute asset URLs so deep links like /devices/<id> load the app.
		paths: { relative: false },
		// Content Security Policy in the page (the inline start script by hash). The server
		// adds what a <meta> policy cannot carry (frame-ancestors) as a header.
		csp: {
			mode: 'hash',
			directives: {
				'default-src': ['self'],
				'script-src': ['self'],
				// Svelte style attributes (e.g. tree indentation) are inline.
				'style-src': ['self', 'unsafe-inline'],
				'img-src': ['self', 'data:'],
				'connect-src': ['self'],
				'object-src': ['none'],
				'base-uri': ['self'],
				'form-action': ['self']
			}
		}
	}
};

export default config;
