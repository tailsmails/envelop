module main

import os
import flag
import net.http
import sync
import rand
import time

const default_user_agents =[
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
	'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.43',
	'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1'
]

fn worker(worker_id int, ch chan string, ua_list[]string, mut wg sync.WaitGroup, timeout_sec int, redirect int) {
	defer { wg.done() }
	mut final_red := false

	for {
		url := <-ch or { break }

		ua_idx := rand.int_in_range(0, ua_list.len) or { 0 }
		random_ua := ua_list[ua_idx]
		
		if redirect != 0 { final_red = true }
		fetch_config := http.FetchConfig{
			url: url
			method: .head
			user_agent: random_ua
			allow_redirect: final_red 
		}
		
		resp := http.fetch(fetch_config) or {
			println('[Worker $worker_id] [!] Timeout/Blocked: $url')
			continue
		}

		println('[Worker $worker_id] [✔] Obfuscated Visit: $url (Status: $resp.status_code)')
		
		time.sleep(10 * time.millisecond)
	}
}

fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application('Envelope')
	fp.version('1.3.0')
	fp.description('Generates background HTTP HEAD requests to obfuscate real web traffic.')
	fp.skip_executable()

	list_arg := fp.string('list', `l`, '', 'Path or URL containing the site list [Required]')
	ua_arg := fp.string('user-agents', `u`, '', 'Path or URL to custom User-Agents list [Optional]')
	timeout_arg := fp.int('timeout', `t`, 5, 'Timeout for HTTP requests in seconds')
	workers_arg := fp.int('workers', `w`, 10, 'Number of concurrent workers (threads)')
	redirect_arg := fp.int('redirect', `r`, 0, 'If you want to enable redirect (0 for false/any for true)')
	count_arg := fp.int('count', `c`, 500, 'Total number of random requests to generate')

	fp.finalize() or {
		eprintln('[!] Error parsing arguments: $err')
		println(fp.usage())
		exit(1)
	}

	if list_arg == '' {
		eprintln('[!] Error: Missing required argument --list')
		println(fp.usage())
		exit(1)
	}

	println('[*] Starting Envelope Session...')
	
	mut raw_content := ''
	if list_arg.starts_with('http://') || list_arg.starts_with('https://') {
		println('[*] Downloading site list from URL: $list_arg')
		resp := http.get(list_arg) or {
			eprintln('[!] Error downloading site list: $err')
			exit(1)
		}
		raw_content = resp.body
	} else {
		println('[*] Reading local site list: $list_arg')
		raw_content = os.read_file(list_arg) or {
			eprintln('[!] Error reading local site file: $err')
			exit(1)
		}
	}

	mut sites :=[]string{}
	for line in raw_content.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed != '' {
			mut url := trimmed
			if !url.starts_with('http://') && !url.starts_with('https://') {
				url = 'http://' + url
			}
			sites << url
		}
	}

	if sites.len == 0 {
		eprintln('[!] Error: The site list is empty.')
		exit(1)
	}
	println('[*] Successfully loaded ${sites.len} sites.')
	
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

		mut loaded_uas :=[]string{}
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
	
	println('[*] Configuration: $workers_arg workers | $timeout_arg sec timeout | $count_arg total requests\n')

	mut wg := sync.new_waitgroup()
	wg.add(workers_arg)

	mut jobs := chan string{cap: 1000}
	
	for i in 1 .. (workers_arg + 1) {
		spawn worker(i, jobs, user_agents, mut wg, timeout_arg, redirect_arg)
	}
	
	for _ in 0 .. count_arg {
		idx := rand.int_in_range(0, sites.len) or { 0 }
		jobs <- sites[idx]
	}

	jobs.close()
	wg.wait()

	println('\n[*] Operation completed successfully.')
}