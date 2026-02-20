/**
 * Example file for running Sekant Intercept.js in a Cloudflare Worker environment.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { InterceptScanner } from './sekant-intercept.node.mjs';

const scanner = new InterceptScanner();

const rules = 
`
rule Base64AndNocase {
    strings:
        $b64 = "secret_command" base64
        $nc  = "SuspiciousPattern" nocase
    condition:
        $b64 or $nc
}

rule RegexMatch {
    strings:
        // Matches "detect_me" or "detect_it" case-insensitive
        $re1 = /detect_(me|it)/i
    condition:
        $re1
}

rule HexAndString {
    strings:
        $s1 = "malicious"
        $h1 = { 64 65 74 65 63 74 } // "detect"
    condition:
        $s1 and $h1
}
`;

scanner.addRules(rules);

export default {
	async fetch(request, env, ctx) {

		const url = new URL(request.url);

		if (request.method.toUpperCase() === 'POST' && url.pathname === '/scan') {
			const body = await request.clone().text();
			const results = await scanner.scan(body);
			const response = new Response(JSON.stringify(results), {
				headers: { 'Content-Type': 'application/json' },
			});
			return response;
		}

		if (url.pathname === '/rules') {
			return new Response(rules, {
				headers: { 'Content-Type': 'text/plain' },
			});
		}

		return new Response('Not Found', { status: 404 });
	},
};
