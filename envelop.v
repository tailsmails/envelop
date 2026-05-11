//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.

module main

import os
import flag
import net.http
import net.urllib
import sync
import rand
import time
import crypto.md5

const default_user_agents = [
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
	'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.43',
	'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
]

struct AppState {
mut:
	sites          []string
	active_path    string
	failure_counts map[string]int
}

fn (shared s AppState) report_failure(url string) {
	lock s {
		s.failure_counts[url]++
		if s.failure_counts[url] >= 3 {
			mut idx := -1
			for i, s_url in s.sites {
				if s_url == url {
					idx = i
					break
				}
			}
			if idx != -1 {
				s.sites.delete(idx)
				// Update the active list file
				mut f := os.create(s.active_path) or { return }
				for site in s.sites {
					f.writeln(site) or { break }
				}
				f.close()
				println('[*] [!] Site ${url} removed from active list due to repeated timeouts.')
			}
		}
	}
}

fn get_base_domain(hostname string) string {
	parts := hostname.split('.')
	if parts.len <= 2 {
		return hostname
	}
	return parts[parts.len - 2] + '.' + parts[parts.len - 1]
}

fn find_related_internal(url string, sites []string) string {
	mut u_str := url
	if !u_str.contains('://') {
		u_str = 'https://' + u_str
	}
	u := urllib.parse(u_str) or { return '' }
	host := u.hostname()
	base := get_base_domain(host)

	mut related_pool := []string{}
	for site in sites {
		if site == url {
			continue
		}
		mut su_str := site
		if !su_str.contains('://') {
			su_str = 'https://' + su_str
		}
		su := urllib.parse(su_str) or { continue }
		shost := su.hostname()
		if shost.ends_with(base) {
			related_pool << site
		}
	}

	if related_pool.len > 0 {
		ridx := rand.int_in_range(0, related_pool.len) or { 0 }
		println('[*] Simulating session: Found related domain ${related_pool[ridx]} for ${url}')
		return related_pool[ridx]
	}
	return ''
}

fn worker(worker_id int, jobs chan string, ua_list []string, mut wg sync.WaitGroup, timeout_sec int, redirect int, proxy_addr string, shared state AppState) {
	defer {
		wg.done()
	}

	mut proxy := &http.HttpProxy(unsafe { nil })
	if proxy_addr != '' {
		p_url := if proxy_addr.contains('://') { proxy_addr } else { 'socks5://' + proxy_addr }
		proxy = http.new_http_proxy(p_url) or {
			eprintln('[Worker ${worker_id}] [!] Invalid Proxy: ${err}')
			unsafe { nil }
		}
	}

	for {
		site := <-jobs or { break }

		mut url := site
		if !url.starts_with('http://') && !url.starts_with('https://') {
			url = 'https://' + url
		}

		ua_idx := rand.int_in_range(0, ua_list.len) or { 0 }
		random_ua := ua_list[ua_idx]

		mut config := http.FetchConfig{
			url: url
			method: .head
			user_agent: random_ua
			read_timeout: timeout_sec * time.second
			write_timeout: timeout_sec * time.second
			allow_redirect: redirect != 0
			proxy: proxy
		}

		resp := http.fetch(config) or {
			println('[Worker ${worker_id}] [!] Connection Failed: ${url} (${err})')
			state.report_failure(site)
			continue
		}

		if resp.status_code >= 200 && resp.status_code < 400 {
			println('[Worker ${worker_id}] [✔] Obfuscated Visit: ${url} (Success)')
		} else {
			println('[Worker ${worker_id}] [!] Visit: ${url} (Status ${resp.status_code})')
		}

		// Random dwell time: 2 to 7 seconds to look like a real user
		dwell := rand.int_in_range(2, 8) or { 3 }
		time.sleep(dwell * time.second)
	}
}

fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application('Envelop')
	fp.version('1.4.0')
	fp.description('Generates background HTTP HEAD requests to obfuscate real web traffic.')
	fp.skip_executable()

	list_arg := fp.string('list', `l`, '', 'Path or URL containing the site list [Required]')
	ua_arg := fp.string('user-agents', `u`, '', 'Path or URL to custom User-Agents list [Optional]')
	proxy_arg := fp.string('proxy', `p`, '', 'SOCKS5 proxy address (e.g. 127.0.0.1:9050) [Optional]')
	timeout_arg := fp.int('timeout', `t`, 5, 'Timeout for HTTP requests in seconds')
	workers_arg := fp.int('workers', `w`, 10, 'Number of concurrent workers (threads)')
	redirect_arg := fp.int('redirect', `r`, 0, 'If you want to enable redirect (0 for false/any for true)')
	count_arg := fp.int('count', `c`, 500, 'Total number of random requests to generate')

	fp.finalize() or {
		eprintln('[!] Error parsing arguments: ${err}')
		println(fp.usage())
		exit(1)
	}

	if list_arg == '' {
		eprintln('[!] Error: Missing required argument --list')
		println(fp.usage())
		exit(1)
	}

	println('[*] Starting Envelope Session...')

	mut active_sites := []string{}
	md5_hash := md5.hexhash(list_arg)
	active_path := 'active_${md5_hash}.txt'

	if os.exists(active_path) {
		println('[*] Found active list, loading: ${active_path}')
		active_content := os.read_file(active_path) or { '' }
		for line in active_content.split_into_lines() {
			trimmed := line.trim_space()
			if trimmed != '' {
				active_sites << trimmed
			}
		}
	}

	if active_sites.len == 0 {
		println('[*] Active list not found or empty. Loading from source: ${list_arg}')
		mut raw_content := ''
		if list_arg.starts_with('http://') || list_arg.starts_with('https://') {
			resp := http.get(list_arg) or {
				eprintln('[!] Error downloading site list: ${err}')
				exit(1)
			}
			raw_content = resp.body
		} else {
			raw_content = os.read_file(list_arg) or {
				eprintln('[!] Error reading local site file: ${err}')
				exit(1)
			}
		}

		for line in raw_content.split_into_lines() {
			trimmed := line.trim_space()
			if trimmed != '' {
				active_sites << trimmed
			}
		}

		if active_sites.len > 0 {
			mut f := os.create(active_path) or {
				eprintln('[!] Could not create active list file: ${err}')
				exit(1)
			}
			for s in active_sites {
				f.writeln(s) or { break }
			}
			f.close()
			println('[*] Created active list: ${active_path}')
		}
	}

	if active_sites.len == 0 {
		eprintln('[!] Error: The site list is empty.')
		exit(1)
	}
	println('[*] Successfully loaded ${active_sites.len} sites.')

	mut user_agents := default_user_agents.clone()
	if ua_arg != '' {
		mut raw_ua_content := ''
		if ua_arg.starts_with('http://') || ua_arg.starts_with('https://') {
			println('[*] Downloading User-Agents list from URL: $ua_arg')
			resp_ua := http.get(ua_arg) or {
				eprintln('[!] Error downloading User-Agents: $err')
				exit(1)
			}
			raw_ua_content = resp_ua.body
		} else {
			println('[*] Reading local User-Agents list: $ua_arg')
			raw_ua_content = os.read_file(ua_arg) or {
				eprintln('[!] Error reading local User-Agents file: $err')
				exit(1)
			}
		}

		mut loaded_uas := []string{}
		for line in raw_ua_content.split_into_lines() {
			trimmed := line.trim_space()
			if trimmed != '' {
				loaded_uas << trimmed
			}
		}

		if loaded_uas.len > 0 {
			user_agents = loaded_uas.clone()
			println('[*] Successfully loaded ${user_agents.len} custom User-Agents.')
		} else {
			println('[!] Warning: Provided User-Agent list is empty, falling back to defaults.')
		}
	}

	if proxy_arg != '' {
		println('[*] Configuration: ${workers_arg} workers | ${timeout_arg} sec timeout | ${count_arg} total requests | Proxy: ${proxy_arg}\n')
	} else {
		println('[*] Configuration: ${workers_arg} workers | ${timeout_arg} sec timeout | ${count_arg} total requests\n')
	}

	shared state := AppState{
		sites: active_sites
		active_path: active_path
		failure_counts: map[string]int{}
	}

	mut wg := sync.new_waitgroup()
	wg.add(workers_arg)

	mut jobs := chan string{cap: 1000}

	for i in 1 .. (workers_arg + 1) {
		spawn worker(i, jobs, user_agents, mut wg, timeout_arg, redirect_arg, proxy_arg, shared
			state)
	}

	for _ in 0 .. count_arg {
		mut url := ''
		mut related := ''
		lock state {
			if state.sites.len > 0 {
				idx := rand.int_in_range(0, state.sites.len) or { 0 }
				url = state.sites[idx]
				if rand.f64() < 0.3 {
					related = find_related_internal(url, state.sites)
				}
			}
		}
		if url != '' {
			jobs <- url
		}
		if related != '' {
			jobs <- related
		}
	}

	jobs.close()
	wg.wait()

	println('\n[*] Operation completed successfully.')
}
