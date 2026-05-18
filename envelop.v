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
import net
import net.ssl
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
	focus_mode     bool
	insecure       bool
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
				println('[*] [!] Site ${url} removed from active list due to repeated failures.')
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

fn dial_proxy(proxy_addr string, host string, port int) !&net.TcpConn {
	mut addr := proxy_addr
	if addr.contains('://') {
		addr = addr.all_after('://')
	}
	mut c := net.dial_tcp(addr)!
	c.write([u8(5), 1, 0])!
	mut g := []u8{len: 2}
	c.read(mut g)!
	if g[0] != 5 || g[1] != 0 {
		c.close() or {}
		return error('socks5 auth failed')
	}
	mut r := [u8(5), 1, 0, 3, u8(host.len)]
	r << host.bytes()
	r << u8(port >> 8)
	r << u8(port & 0xff)
	c.write(r)!
	mut rsp := []u8{len: 256}
	c.read(mut rsp)!
	if rsp[1] != 0 {
		c.close() or {}
		return error('socks5 connection refused')
	}
	return c
}

fn worker(worker_id int, jobs chan string, ua_list []string, mut wg sync.WaitGroup, timeout_sec int, redirect int, proxy_addr string, shared state AppState) {
	defer {
		wg.done()
	}

	for {
		site := <-jobs or { break }

		mut url_str := site
		if !url_str.contains('://') {
			url_str = 'https://' + url_str
		}

		u := urllib.parse(url_str) or {
			println('[Worker ${worker_id}] [!] Invalid URL: ${url_str}')
			continue
		}

		is_https := u.scheme == 'https'
		host := u.hostname()
		mut port := u.port().int()
		if port == 0 {
			port = if is_https { 443 } else { 80 }
		}

		mut conn := if proxy_addr != '' {
			dial_proxy(proxy_addr, host, port) or {
				println('[Worker ${worker_id}] [!] Proxy Connection Failed for ${url_str}: ${err}')
				state.report_failure(site)
				continue
			}
		} else {
			net.dial_tcp('${host}:${port}') or {
				println('[Worker ${worker_id}] [!] Connection Failed: ${url_str} (${err})')
				state.report_failure(site)
				continue
			}
		}

		conn.set_read_timeout(timeout_sec * time.second)
		conn.set_write_timeout(timeout_sec * time.second)

		ua_idx := rand.int_in_range(0, ua_list.len) or { 0 }
		random_ua := ua_list[ua_idx]
		path := if u.path == '' { '/' } else { u.path }
		head_request := 'HEAD ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${random_ua}\r\nConnection: close\r\n\r\n'

		if is_https {
			mut validate := true
			lock state {
				if state.insecure {
					validate = false
				}
			}
			// Attempt to use system default CA certificates if none provided and validation is enabled
			mut verify := ''
			if validate {
				// Common paths for CA certificates on Linux
				ca_paths := [
					'/etc/ssl/certs/ca-certificates.crt',
					'/etc/pki/tls/certs/ca-bundle.crt',
					'/etc/ssl/ca-bundle.pem',
					'/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
					'/etc/ssl/cert.pem',
				]
				for p in ca_paths {
					if os.exists(p) {
						verify = p
						break
					}
				}
			}

			mut s := ssl.new_ssl_conn(validate: validate, verify: verify) or {
				println('[Worker ${worker_id}] [!] SSL Initialization Failed: ${err}')
				conn.close() or {}
				continue
			}

			// In case of mbedtls, we can force NONE mode if insecure is requested.
			// This bypasses a limitation in V's net.ssl where 'validate: false'
			// translates to MBEDTLS_SSL_VERIFY_OPTIONAL which still performs some checks.
			$if !d_use_openssl ? {
				if !validate {
					unsafe {
						C.mbedtls_ssl_conf_authmode(&s.conf, 0)
					}
				}
			}

			s.connect(mut conn, host) or {
				println('[Worker ${worker_id}] [!] SSL Handshake Failed for ${url_str}: ${err}')
				state.report_failure(site)
				conn.close() or {}
				continue
			}
			s.write_string(head_request) or {
				s.close() or {}
				continue
			}
			mut buf := []u8{len: 1024}
			n := s.read(mut buf) or {
				println('[Worker ${worker_id}] [!] Read Timeout/Error: ${url_str}')
				state.report_failure(site)
				s.close() or {}
				continue
			}
			if n > 0 {
				println('[Worker ${worker_id}] [✔] Obfuscated Visit: ${url_str} (Success)')
			}
			s.close() or {}
		} else {
			conn.write_string(head_request) or {
				conn.close() or {}
				continue
			}
			mut buf := []u8{len: 1024}
			n := conn.read(mut buf) or {
				println('[Worker ${worker_id}] [!] Read Timeout/Error: ${url_str}')
				state.report_failure(site)
				conn.close() or {}
				continue
			}
			if n > 0 {
				println('[Worker ${worker_id}] [✔] Obfuscated Visit: ${url_str} (Success)')
			}
			conn.close() or {}
		}

		// Random dwell time: 2 to 7 seconds to look like a real user
		// In focus mode, we stay longer (15 to 45 seconds)
		mut dwell_min := 2
		mut dwell_max := 8
		lock state {
			if state.focus_mode {
				dwell_min = 15
				dwell_max = 45
			}
		}

		dwell := rand.int_in_range(dwell_min, dwell_max) or { dwell_min }
		if dwell > 10 {
			println('[Worker ${worker_id}] [*] Focus Mode: Staying on ${host} for ${dwell} seconds...')
		}
		time.sleep(dwell * time.second)
	}
}

fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application('Envelop')
	fp.version('1.4.1')
	fp.description('Generates background HTTP HEAD requests to obfuscate real web traffic.')
	fp.skip_executable()

	list_arg := fp.string('list', `l`, '', 'Path or URL containing the site list [Required]')
	ua_arg := fp.string('user-agents', `u`, '', 'Path or URL to custom User-Agents list [Optional]')
	proxy_arg := fp.string('proxy', `p`, '', 'SOCKS5 proxy address (e.g. 127.0.0.1:9050) [Optional]')
	timeout_arg := fp.int('timeout', `t`, 5, 'Timeout for HTTP requests in seconds')
	workers_arg := fp.int('workers', `w`, 10, 'Number of concurrent workers (threads)')
	redirect_arg := fp.int('redirect', `r`, 0, 'If you want to enable redirect (0 for false/any for true)')
	count_arg := fp.int('count', `c`, 500, 'Total number of random requests to generate')
	focus_arg := fp.bool('focus', `f`, false, 'Enable focus mode (simulates longer site visits)')
	insecure_arg := fp.bool('insecure', `k`, false, 'Allow insecure SSL connections (disables certificate validation)')

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

	mut config_msg := '[*] Configuration: ${workers_arg} workers | ${timeout_arg} sec timeout | ${count_arg} total requests'
	if focus_arg {
		config_msg += ' | Focus Mode: Enabled'
	}
	if proxy_arg != '' {
		config_msg += ' | Proxy: ${proxy_arg}'
	}
	println(config_msg + '\n')

	shared state := AppState{
		sites: active_sites
		active_path: active_path
		failure_counts: map[string]int{}
		focus_mode: focus_arg
		insecure: insecure_arg
	}

	if insecure_arg {
		println('[!] Warning: Insecure mode enabled. SSL certificate validation is disabled.')
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
		mut related := []string{}
		lock state {
			if state.sites.len > 0 {
				idx := rand.int_in_range(0, state.sites.len) or { 0 }
				url = state.sites[idx]

				related_chance := if state.focus_mode { 0.7 } else { 0.3 }
				related_max := if state.focus_mode { 5 } else { 1 }

				if rand.f64() < related_chance {
					num_related := if state.focus_mode {
						rand.int_in_range(1, related_max + 1) or { 1 }
					} else {
						1
					}
					for _ in 0 .. num_related {
						r := find_related_internal(url, state.sites)
						if r != '' {
							related << r
						}
					}
				}
			}
		}
		if url != '' {
			jobs <- url
		}
		for r in related {
			jobs <- r
		}
	}

	jobs.close()
	wg.wait()

	println('\n[*] Operation completed successfully.')
}
