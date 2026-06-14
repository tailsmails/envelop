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
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
	'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
	'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
]

struct App {
mut:
	sites          []string
	active_path    string
	failure_counts map[string]int
	focus_mode     bool
	user_agents    []string
	timeout        int
	proxy_addr     string
}

fn (shared app App) report_failure(url string) {
	lock app {
		app.failure_counts[url]++
		if app.failure_counts[url] >= 3 {
			idx := app.sites.index(url)
			if idx != -1 {
				app.sites.delete(idx)
				app.save_active_list() or {
					eprintln('[!] Failed to update active list file: ${err}')
				}
				eprintln('[*] [!] Site ${url} removed from active list due to repeated network failures.')
			}
		}
	}
}

fn (app &App) save_active_list() ! {
	mut f := os.create(app.active_path)!
	defer {
		f.close()
	}
	for site in app.sites {
		f.writeln(site)!
	}
}

fn get_base_domain(hostname string) string {
	parts := hostname.split('.')
	if parts.len <= 2 {
		return hostname
	}
	return parts[parts.len - 2..].join('.')
}

fn (app &App) find_related_internal(url string) string {
	mut u_str := url
	if !u_str.contains('://') {
		u_str = 'https://' + u_str
	}
	u := urllib.parse(u_str) or { return '' }
	host := u.hostname()
	base := get_base_domain(host)

	mut related_pool := []string{}
	for site in app.sites {
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

fn worker(worker_id int, jobs chan string, mut wg sync.WaitGroup, shared app App) {
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
			eprintln('[Worker ${worker_id}] [!] Invalid URL: ${url_str}')
			continue
		}

		host := u.hostname()
		mut port := u.port().int()
		if port == 0 {
			port = if u.scheme == 'https' { 443 } else { 80 }
		}
		
		mut conn := if rlock app {
			app.proxy_addr
		} != '' {
			dial_proxy(rlock app {
				app.proxy_addr
			}, host, port) or {
				eprintln('[Worker ${worker_id}] [!] Proxy Connection Failed for ${url_str}: ${err}')
				app.report_failure(site)
				continue
			}
		} else {
			net.dial_tcp('${host}:${port}') or {
				eprintln('[Worker ${worker_id}] [!] Connection Failed: ${url_str} (${err})')
				app.report_failure(site)
				continue
			}
		}

		timeout := rlock app {
			app.timeout
		}
		conn.set_read_timeout(timeout * time.second)
		conn.set_write_timeout(timeout * time.second)

		if u.scheme == 'https' {
			mut ssl_conn := ssl.new_ssl_conn() or {
				eprintln('[Worker ${worker_id}] [!] SSL Client Initialization Failed: ${err}')
				conn.close() or {}
				continue
			}
			ssl_conn.set_read_timeout(timeout * time.second)
			ssl_conn.connect(mut *conn, host) or {
				eprintln('[Worker ${worker_id}] [!] SSL Handshake Failed for ${host}: ${err}')
				conn.close() or {}
				continue
			}
			
			perform_get_request(worker_id, mut ssl_conn, u, rlock app {
				app.user_agents
			}) or {
				eprintln('[Worker ${worker_id}] [!] Request Failed: ${url_str} (${err})')
			}
			ssl_conn.close() or {}
		} else {
			perform_get_request(worker_id, mut *conn, u, rlock app {
				app.user_agents
			}) or {
				eprintln('[Worker ${worker_id}] [!] Request Failed: ${url_str} (${err})')
			}
		}
		conn.close() or {}

		mut dwell_min := 2
		mut dwell_max := 8
		if rlock app {
			app.focus_mode
		} {
			dwell_min = 15
			dwell_max = 45
		}

		dwell := rand.int_in_range(dwell_min, dwell_max) or { dwell_min }
		time.sleep(dwell * time.second)
	}
}

interface Connection {
mut:
	write_string(s string) !int
	read(mut buf []u8) !int
}

fn get_stealth_headers(ua string, host string) string {
	mut headers := 'Host: ${host}\r\n' +
		'User-Agent: ${ua}\r\n' +
		'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n' +
		'Accept-Language: en-US,en;q=0.9\r\n' +
		'Upgrade-Insecure-Requests: 1\r\n' +
		'Sec-Fetch-Mode: navigate\r\n' +
		'Sec-Fetch-Dest: document\r\n' +
		'Sec-Fetch-Site: none\r\n' +
		'Sec-Fetch-User: ?1\r\n'
		
	referers := [
		'https://www.google.com/',
		'https://www.bing.com/',
		'https://duckduckgo.com/',
		'https://t.co/',
		'https://news.ycombinator.com/'
	]
	ref_idx := rand.int_in_range(0, referers.len) or { 0 }
	headers += 'Referer: ${referers[ref_idx]}\r\n'
	
	if ua.contains('Windows') {
		headers += 'Sec-Ch-Ua-Platform: "Windows"\r\n'
		if ua.contains('Edg') {
			headers += 'Sec-Ch-Ua: "Not/A)Brand";v="99", "Microsoft Edge";v="124", "Chromium";v="124"\r\n'
		} else {
			headers += 'Sec-Ch-Ua: "Not/A)Brand";v="99", "Google Chrome";v="124", "Chromium";v="124"\r\n'
		}
		headers += 'Sec-Ch-Ua-Mobile: ?0\r\n'
	} else if ua.contains('Macintosh') {
		headers += 'Sec-Ch-Ua-Platform: "macOS"\r\n'
		headers += 'Sec-Ch-Ua-Mobile: ?0\r\n'
	} else if ua.contains('iPhone') {
		headers += 'Sec-Ch-Ua-Platform: "iOS"\r\n'
		headers += 'Sec-Ch-Ua-Mobile: ?1\r\n'
	} else if ua.contains('Linux') {
		headers += 'Sec-Ch-Ua-Platform: "Linux"\r\n'
		headers += 'Sec-Ch-Ua-Mobile: ?0\r\n'
	}

	headers += 'Connection: close\r\n\r\n'
	return headers
}

fn perform_get_request(worker_id int, mut conn Connection, u urllib.URL, ua_list []string) ! {
	ua_idx := rand.int_in_range(0, ua_list.len) or { 0 }
	random_ua := ua_list[ua_idx]
	
	mut path := if u.path == '' { '/' } else { u.path }
	
	if rand.f64() < 0.25 {
		queries := ['ref=google', 'utm_source=feed', 'lang=en', 'v=${rand.int_in_range(10, 99) or { 12 }}']
		q_idx := rand.int_in_range(0, queries.len) or { 0 }
		if path.contains('?') {
			path += '&' + queries[q_idx]
		} else {
			path += '?' + queries[q_idx]
		}
	}

	host := u.hostname()
	get_request := 'GET ${path} HTTP/1.1\r\n' + get_stealth_headers(random_ua, host)

	conn.write_string(get_request)!
	
	mut buf := []u8{len: 4096}
	mut total_read := 0
	for {
		n := conn.read(mut buf) or { break }
		if n <= 0 { break }
		total_read += n
		
		if total_read > 500 * 1024 {
			break
		}
	}
	
	if total_read > 0 {
		println('[Worker ${worker_id}] [✔] GET Visit: ${u} (Success, Read: ${total_read} bytes)')
	}
}

fn load_list(path_or_url string) ![]string {
	mut raw_content := ''
	if path_or_url.starts_with('http://') || path_or_url.starts_with('https://') {
		resp := http.get(path_or_url)!
		raw_content = resp.body
	} else {
		raw_content = os.read_file(path_or_url)!
	}

	mut sites := []string{}
	for line in raw_content.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed != '' {
			sites << trimmed
		}
	}
	return sites
}

fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application('Envelop')
	fp.version('1.4.1')
	fp.description('Generates background HTTP GET requests to obfuscate real web traffic.')
	fp.skip_executable()

	list_arg := fp.string('list', `l`, '', 'Path or URL containing the site list [Required]')
	ua_arg := fp.string('user-agents', `u`, '', 'Path or URL to custom User-Agents list [Optional]')
	proxy_arg := fp.string('proxy', `p`, '',
		'SOCKS5 proxy address (e.g. 127.0.0.1:9050) [Optional]')
	timeout_arg := fp.int('timeout', `t`, 5, 'Timeout for HTTP requests in seconds')
	workers_arg := fp.int('workers', `w`, 10, 'Number of concurrent workers (threads)')
	_ := fp.int('redirect', `r`, 0, 'If you want to enable redirect (ignored in current version)')
	count_arg := fp.int('count', `c`, 500, 'Total number of random requests to generate')
	focus_arg := fp.bool('focus', `f`, false, 'Enable focus mode (simulates longer site visits)')

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

	println('[*] Starting Envelope Session ...')

	mut active_sites := []string{}
	md5_hash := md5.hexhash(list_arg)
	active_path := 'active_${md5_hash}.txt'

	if os.exists(active_path) {
		println('[*] Found active list, loading: ${active_path}')
		active_sites = load_list(active_path) or { []string{} }
	}

	if active_sites.len == 0 {
		println('[*] Active list not found or empty. Loading from source: ${list_arg}')
		active_sites = load_list(list_arg) or {
			eprintln('[!] Error loading site list: ${err}')
			exit(1)
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
		println('[*] Loading User-Agents list: ${ua_arg}')
		mut loaded_uas := load_list(ua_arg) or {
			eprintln('[!] Error loading User-Agents: ${err}')
			exit(1)
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

	shared app := App{
		sites:          active_sites
		active_path:    active_path
		failure_counts: map[string]int{}
		focus_mode:     focus_arg
		user_agents:    user_agents
		timeout:        timeout_arg
		proxy_addr:     proxy_arg
	}

	mut wg := sync.new_waitgroup()
	wg.add(workers_arg)

	mut jobs := chan string{cap: 1000}

	for i in 1 .. (workers_arg + 1) {
		spawn worker(i, jobs, mut wg, shared app)
	}

	for _ in 0 .. count_arg {
		mut url := ''
		mut related := []string{}
		lock app {
			if app.sites.len > 0 {
				idx := rand.int_in_range(0, app.sites.len) or { 0 }
				url = app.sites[idx]

				related_chance := if app.focus_mode { 0.7 } else { 0.3 }
				related_max := if app.focus_mode { 5 } else { 1 }

				if rand.f64() < related_chance {
					num_related := if app.focus_mode {
						rand.int_in_range(1, related_max + 1) or { 1 }
					} else {
						1
					}
					for _ in 0 .. num_related {
						r := app.find_related_internal(url)
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
