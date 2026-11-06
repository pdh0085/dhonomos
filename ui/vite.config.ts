import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	server: {
		// During `npm run dev`, forward API calls to a locally running `dhonomos`.
		proxy: { '/api': 'http://127.0.0.1:8080' }
	},
	plugins: [sveltekit()]
});
