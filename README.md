# httpx-to-burp

Convert [httpx](https://github.com/projectdiscovery/httpx) CSV output into a Burp Suite Target Scope `.txt` file (`Target > Scope > Load`).

## Install

```bash
pipx install git+https://github.com/Kraus17th/httpx-to-burp-scope.git
```

Update:

```bash
pipx upgrade httpx-to-burp
```

From a local clone:

```bash
pipx install .
```

## Usage

```bash
httpx-to-burp -i httpx-result.csv -m basic
httpx-to-burp -i httpx-result.csv -m advanced-exact
httpx-to-burp -i httpx-result.csv -m advanced-wildcard
httpx-to-burp -i httpx-result.csv -m advanced-wildcard --skip-cdn --hosts-only
httpx-to-burp -i httpx-result.csv -m basic -o my-scope.txt
```

Default output: `burp-scope.txt`.

| Mode | Output | Burp |
|---|---|---|
| `basic` | hosts + IPs | Scope > Load |
| `advanced-exact` | regex `^host$` + IPs | enable **Use advanced scope control**, then Load |
| `advanced-wildcard` | regex `^(.*\.)?apex$` + IPs | same |

Flags: `--skip-cdn`, `--hosts-only`, `--ips-only`, `-v`.

## Without pipx

```bash
python3 httpx_to_burp.py -i httpx-result.csv -m basic
```
