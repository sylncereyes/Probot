# Probot
Ultra-Fast Async URL Scanner v1

Usage:
  python3 main.py [options]

Input:
  -l, --list FILE            Read input from file (one host/URL per line)
  -u, --target URL [URL...]  Provide one or more targets on the command line
                             (also supports piped input: cat list.txt | python3 main.py)

Scanning Options:
  --alive                    Only display alive sites (drop dead/timeouts)
  -sc, --status-code         Display HTTP status code
  -rt, --response-time       Display response time (ms)
  -title                     Display <title> tag
  -ip                        Display resolved IP address
  -server                    Display server header
  --detect-waf               Detect WAF providers (Cloudflare, Sucuri, Imperva, Akamai...)
  --cdn-check                Detect CDN provider (Cloudflare, CloudFront, Fastly...)
  -td, --tech-detect         Detect technologies in use (compact Wappalyzer dataset)

Performance & Output:
  -t, --threads N            Concurrency (default: 50)
  -timeout N                 Request timeout in seconds (default: 10)
  -o, --output FILE          Save output to file
  -silent                    Disable banner and extra startup text
  -h, --help                 Show this help message
