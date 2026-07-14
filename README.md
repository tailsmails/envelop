# Envelop

Envelop is a lightweight, concurrent web traffic obfuscation tool written in the V programming language. It is designed to generate background HTTP GET requests to a specified list of websites. By creating randomized, realistic network noise, Envelop helps mask your actual web browsing activity and enhances your privacy.

## Features

* **High Concurrency:** Utilizes lightweight concurrent workers to generate requests rapidly without blocking the main thread.
* **Flexible Input Sources:** Load your target website lists and custom User-Agent lists from either local text files or remote URLs.
* **Realistic GET Traffic with Bandwidth Control:** Uses raw TCP sockets to send realistic `GET` requests complete with standard browser headers (Accept, Accept-Language, etc.), capping page downloads to 500 KB to simulate complete page loads without excessive bandwidth consumption.
* **SOCKS5 Proxy Support:** Route all generated traffic through SOCKS5 proxies (e.g., Tor or local proxy interfaces) to mask the originating IP.
* **Highly Customizable:** Offers command-line flags to easily adjust the number of concurrent workers, connection timeouts, and the total volume of requests generated.
* **Focus Mode:** Simulates a real user focusing on a specific site by staying longer and visiting more related internal pages.
* **Automatic Fallbacks:** Includes a built-in list of common, up-to-date User-Agents in case a custom list is not provided or fails to load.

## Prerequisites

To compile and run this project, you must have the [V programming language](https://vlang.io/) installed on your system.

## Quick Install

```sh
apt update -y && apt install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/envelop && cd envelop && v -prod envelop.v -o envelop && ln -sf $(pwd)/envelop $PREFIX/bin/envelop
```

Build Instructions

1.  Clone or download the source code to your local machine.
2.  Open your terminal and navigate to the project directory.
3.  Compile the application using the V compiler. For the best performance,
    compile it with the production flag:
```sh
v -prod envelop.v -o envelop
```
Usage

You can run the compiled executable directly from your terminal. The only
strictly required argument is the --list flag, which points to your target
websites.

./envelop --list <path_or_url> [options]

Command-Line Arguments

  - -l, --list (Required): Path or URL containing the site list. Each domain or
    URL must be on a new line.
  - -u, --user-agents (Optional): Path or URL to a custom User-Agents list. Each
    User-Agent must be on a new line.
  - -p, --proxy (Optional): SOCKS5 proxy address (e.g. 127.0.0.1:9050 or
    127.0.0.1:1080).
  - -t, --timeout (Optional): Read and write timeout for HTTP requests in
    seconds. Default is 5.
  - -w, --workers (Optional): Number of concurrent workers (threads) to spawn.
    Default is 10.
  - -r, --redirect (Optional): Pass 0 to disable redirects, or any other integer
    to enable them. (Note: Currently ignored in this version).
  - -c, --count (Optional): Total number of random requests to generate across
    all workers before exiting. Default is 500.
  - -f, --focus (Optional): Enable focus mode. This simulates longer visits
    (15-45 seconds) and increases the frequency of related site visits.

Examples

Basic Usage Read a local file named sites.txt and generate the default 500
requests using 10 workers:
```sh
./envelop --list sites.txt
```
SOCKS5 Proxy (Tor) Route all generated HTTP GET requests through a local SOCKS5
proxy like Tor:
```sh
./envelop --list sites.txt --proxy 127.0.0.1:9050
```
Remote Site List Fetch the target websites directly from a remote URL:
```sh
./envelop -l https://example.com/my_sites.txt
```
Advanced Configuration Generate 5000 requests using 50 workers, a 10-second
timeout, and a remote custom User-Agent list over a local SOCKS5 proxy:
```sh
./envelop -l sites.txt -u https://example.com/user_agents.txt -p 127.0.0.1:1080 -w 50 -t 10 -c 5000
```
Input File Format

Both the site list and the custom User-Agent list should be plain text files
with one entry per line.

sites.txt:
```text
google.com
https://github.com
wikipedia.org
```
*Note: If the http:// or https:// protocol is missing, the tool will
automatically prepend https://*
