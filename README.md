# crawlexsses

crawlexsses is a Unix-first CLI that chains together best-in-class recon tools to discover potential XSS endpoints at scale. It automates:

- Subdomain discovery and probing
- Historical URL collection (multiple modes)
- Smart filtering and normalization for XSS parameters
- Automated XSS testing via KNOXSS Pro (through `knoxnl`)

Author: 0xhollow

## Features

- Subfinder → httpx live host probing
- History modes:
  - `waymore`: Wayback Machine URLs only
  - `waymore-katana`: Wayback + crawling
  - `all`: Wayback + crawling + Common Crawl/AlienVault via GAU
- URL filtering: `gf xss` + extension blacklist + `uro` normalization + `httpx` verification
- XSS testing: `knoxnl` with KNOXSS Pro API
- Verbose mode and simple rate limiting
- All outputs end with `.txt`

## Installation

### Prerequisites (external tools)

Install these on Linux/macOS and ensure they’re in your PATH:

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Katana (crawler)
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Waymore (Wayback Machine, etc.)
pip3 install waymore

# GAU (Common Crawl/AlienVault)
go install -v github.com/lc/gau/v2/cmd/gau@latest

# GF + XSS patterns
go install -v github.com/tomnomnom/gf@latest
mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf 2>/dev/null || true

# URO (URL normalization)
pip3 install uro

# knoxnl (KNOXSS Pro client)
# Install per the official repo instructions (language/packaging can change over time):
#   https://github.com/xnl-h4ck3r/knoxnl
# For many environments, one of these works:
# pip3 install knoxnl
# or
# go install -v github.com/xnl-h4ck3r/knoxnl@latest
```

### KNOXSS Pro API key (required for knoxnl)

You must have an active KNOXSS Pro subscription and API key. Get it from your KNOXSS account:

- KNOXSS Pro: https://knoxss.pro/

Configure `knoxnl` with your API key as documented in its repository. Common setups seen in the wild include either a config file or an environment variable:

1) Config file (typical):

```yaml
# ~/.config/knoxnl/config.yml
API_KEY: YOUR_KNOXSS_API_KEY
```

2) Environment variable (if your knoxnl version supports it):

```bash
export KNOXSS_API_KEY="YOUR_KNOXSS_API_KEY"
```

### Install crawlexsses

```bash
# Clone the repository
git clone https://github.com/0xhollow/crawlexsses.git
cd crawlexsses

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x crawlexsses.py

# Optional: Install system-wide
pip3 install .
```

## Usage

```bash
# Basic usage - all modes
python3 crawlexsses.py -d example.com

# Specific modes
python3 crawlexsses.py -d example.com --mode waymore
python3 crawlexsses.py -d example.com --mode waymore-katana
python3 crawlexsses.py -d example.com --mode all

# Verbose + rate limit
python3 crawlexsses.py -d example.com --mode all -v -r 100

# If installed via pip, you can also run:
crawlexsses -d example.com --mode all -v
```

### Options

- `-d, --domain`: Target domain (required)
- `-m, --mode`: History collection mode
  - `waymore`: Wayback machine only
  - `waymore-katana`: Wayback + JavaScript crawling
  - `all`: All sources (default)
- `-r, --rate-limit`: Batch size for rate limiting (default: 0 = no limit)
- `-v, --verbose`: Enable verbose output

## Output files (.txt)

All output files use `.txt` extension:

- `subs.txt`: Live subdomains
- `xss-waymore.txt`: Wayback machine URLs
- `xss-katana.txt`: JavaScript-discovered URLs
- `xss-gau.txt`: Common Crawl/AlienVault URLs
- `xss.txt`: Filtered and merged URLs ready for testing
- `xssoutput.txt`: Knoxnl test results

## How it works (pipeline)

1. **Subdomain Discovery**: Find subdomains with subfinder
2. **HTTP Probing**: Validate live hosts with httpx
3. **History Collection**: Gather URLs based on selected mode
4. **Merging**: Combine all URL sources
5. **Filtering**: Remove static files and normalize URLs
6. **Testing**: Run XSS tests with knoxnl

## Thanks and credits

This project stands on the shoulders of giants. Immense thanks to the authors and maintainers of:

- ProjectDiscovery — `subfinder`, `httpx`, `katana`: https://github.com/projectdiscovery
- xnl-h4ck3r — `waymore`, `knoxnl`: https://github.com/xnl-h4ck3r
- lc — `gau`: https://github.com/lc/gau
- tomnomnom — `gf`: https://github.com/tomnomnom/gf
- s0md3v — `uro`: https://github.com/s0md3v/uro
- Brute Logic — KNOXSS Pro: https://knoxss.pro/

Please support and star their projects.

## License

MIT — see `LICENSE`.

## Disclaimer

Use only on targets you have explicit permission to test. You are solely responsible for complying with all laws and regulations.
