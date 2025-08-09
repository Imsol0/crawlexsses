#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Iterable, List, Optional, Sequence, Tuple

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = ""
        RESET = ""
    class Style:
        BRIGHT = ""
        RESET_ALL = ""


def print_banner() -> None:
    if HAS_COLOR:
        color_start = Fore.GREEN + Style.BRIGHT
        color_end = Style.RESET_ALL
    else:
        color_start = ""
        color_end = ""
    
    banner = f"""{color_start}
 ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██╗  ██╗███████╗███████╗███████╗███████╗
██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝╚██╗██╔╝██╔════╝██╔════╝██╔════╝██╔════╝
██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗   ╚███╔╝ ███████╗███████╗█████╗  ███████╗
██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝   ██╔██╗ ╚════██║╚════██║██╔══╝  ╚════██║
╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██╔╝ ██╗███████║███████║███████╗███████║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝
                                                                                          
                           XSS Discovery Tool - Find those hidden XSS gems!
                                      Author: 0xhollow
{color_end}"""
    print(banner)


def log_info(message: str) -> None:
    sys.stdout.write(message + "\n")
    sys.stdout.flush()


def ensure_tools_exist(tools: Sequence[str]) -> Tuple[bool, List[str]]:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    return (len(missing) == 0, missing)


def run_command(
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    capture_output: bool = True,
    output_file: Optional[str] = None,
    append: bool = False,
    verbose: bool = False,
) -> subprocess.CompletedProcess:
    if verbose:
        sys.stderr.write(f"[cmd] {' '.join(args)}\n")
        sys.stderr.flush()

    stdout_dest = subprocess.PIPE
    if output_file is not None:
        mode = "ab" if append else "wb"
        stdout_dest = open(output_file, mode)

    try:
        proc = subprocess.run(
            args,
            input=input_text.encode() if input_text is not None else None,
            stdout=stdout_dest,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        if output_file is not None and hasattr(stdout_dest, "close"):
            stdout_dest.close()

    if verbose and proc.stderr:
        sys.stderr.write(proc.stderr.decode(errors="ignore"))
        sys.stderr.flush()

    return proc


def read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def write_lines(path: str, lines: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")


def append_lines(path: str, lines: Iterable[str]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")


def unique_preserve_order(lines: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result


def chunked(seq: Sequence[str], size: int) -> Iterable[List[str]]:
    if size <= 0:
        yield list(seq)
        return
    for i in range(0, len(seq), size):
        yield list(seq[i : i + size])


def subfinder_to_httpx(
    domain: str, subs_out: str, rate_limit: int, verbose: bool
) -> Tuple[int, int]:
    # subfinder -d domain -all | httpx -silent -> subs_out
    subfinder_args = ["subfinder", "-d", domain, "-all", "-silent"]
    proc = run_command(subfinder_args, capture_output=True, verbose=verbose)
    if proc.returncode != 0:
        raise RuntimeError("subfinder failed")
    subdomains = proc.stdout.decode(errors="ignore").splitlines() if proc.stdout else []
    subdomains = [s.strip() for s in subdomains if s.strip()]
    if not subdomains:
        write_lines(subs_out, [])
        return (0, 0)

    # Pipe to httpx in chunks to respect a simple rate limit
    if os.path.exists(subs_out):
        os.remove(subs_out)

    for idx, batch in enumerate(
        chunked(subdomains, rate_limit if rate_limit > 0 else len(subdomains))
    ):
        input_text = "\n".join(batch) + "\n"
        httpx_args = ["httpx", "-silent"]
        proc2 = run_command(
            httpx_args,
            input_text=input_text,
            output_file=subs_out,
            append=(idx != 0),
            verbose=verbose,
        )
        if proc2.returncode != 0:
            raise RuntimeError("httpx failed while probing subdomains")
        if rate_limit > 0:
            time.sleep(0.1)

    live = len(read_lines(subs_out))
    return (len(subdomains), live)


def run_waymore(subs_file: str, out_file: str, verbose: bool) -> int:
    # waymore -i subs -mode U -oU out
    args = ["waymore", "-i", subs_file, "-mode", "U", "-oU", out_file]
    proc = run_command(args, verbose=verbose)
    if proc.returncode != 0:
        raise RuntimeError("waymore failed")
    return len(read_lines(out_file))


def run_katana(subs_file: str, out_file: str, verbose: bool) -> int:
    # katana -list subs -headless -jc -d 5 -o out
    args = ["katana", "-list", subs_file, "-headless", "-jc", "-d", "5", "-o", out_file]
    proc = run_command(args, verbose=verbose)
    if proc.returncode != 0:
        raise RuntimeError("katana failed")
    return len(read_lines(out_file))


def run_gau(subs_file: str, out_file: str, rate_limit: int, verbose: bool) -> int:
    # cat subs | gau --subs -o out
    subs = read_lines(subs_file)
    if not subs:
        write_lines(out_file, [])
        return 0
    if os.path.exists(out_file):
        os.remove(out_file)
    batches = list(chunked(subs, rate_limit if rate_limit > 0 else len(subs)))
    for i, batch in enumerate(batches):
        input_text = "\n".join(batch) + "\n"
        args = ["gau", "--subs", "-o", out_file]
        proc = run_command(args, input_text=input_text, verbose=verbose)
        if proc.returncode != 0:
            raise RuntimeError("gau failed")
        if rate_limit > 0 and i + 1 < len(batches):
            time.sleep(0.1)
    return len(read_lines(out_file))


def merge_histories(outputs: Sequence[str], merged_out: str) -> None:
    all_lines: List[str] = []
    for path in outputs:
        all_lines.extend(read_lines(path))
    merged = unique_preserve_order(all_lines)
    write_lines(merged_out, merged)


EXCLUDE_EXT_REGEX = re.compile(
    r"\.(css|woff|woff2|txt|js|m4r|m4p|m4b|ipa|asa|pkg|crash|asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|webp|json|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|webm|mpp|_otf|odb|odc|odf|odg|odp|ods|odt|ogg|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|tif|tiff|_ttf|wav|wma|wri|xla|xls|xlsx|xlt|xlw|zip)(?:$|\?)",
    re.IGNORECASE,
)


def filter_with_gf_uro_httpx(
    merged_in: str,
    final_out: str,
    rate_limit: int,
    verbose: bool,
) -> Tuple[int, int, int, int]:
    lines = read_lines(merged_in)
    if not lines:
        write_lines(final_out, [])
        return (0, 0, 0, 0)

    # sort -u equivalent
    lines = sorted(set(lines))

    # gf xss
    gf_args = ["gf", "xss"]
    proc_gf = run_command(gf_args, input_text="\n".join(lines) + "\n", verbose=verbose)
    if proc_gf.returncode != 0:
        raise RuntimeError("gf xss failed")
    gf_lines = (
        proc_gf.stdout.decode(errors="ignore").splitlines() if proc_gf.stdout else []
    )

    # grep '=' and exclude by extension (egrep -iv ...)
    filtered = [
        url for url in gf_lines if "=" in url and not EXCLUDE_EXT_REGEX.search(url)
    ]
    if not filtered:
        write_lines(final_out, [])
        return (len(gf_lines), 0, 0, 0)

    # uro normalization
    if os.path.exists(final_out):
        os.remove(final_out)
    normalized_all: List[str] = []
    for batch in chunked(filtered, rate_limit if rate_limit > 0 else len(filtered)):
        input_text = "\n".join(batch) + "\n"
        proc_uro = run_command(["uro"], input_text=input_text, verbose=verbose)
        if proc_uro.returncode != 0:
            raise RuntimeError("uro failed")
        normalized_all.extend(
            proc_uro.stdout.decode(errors="ignore").splitlines() if proc_uro.stdout else []
        )
        if rate_limit > 0:
            time.sleep(0.05)

    normalized_all = unique_preserve_order([s for s in normalized_all if s.strip()])
    if not normalized_all:
        write_lines(final_out, [])
        return (len(gf_lines), len(filtered), 0, 0)

    # httpx to probe
    probed_all: List[str] = []
    for batch in chunked(
        normalized_all, rate_limit if rate_limit > 0 else len(normalized_all)
    ):
        input_text = "\n".join(batch) + "\n"
        proc_httpx = run_command(["httpx", "-silent"], input_text=input_text, verbose=verbose)
        if proc_httpx.returncode != 0:
            raise RuntimeError("httpx failed while probing URLs")
        probed_all.extend(
            proc_httpx.stdout.decode(errors="ignore").splitlines()
            if proc_httpx.stdout
            else []
        )
        if rate_limit > 0:
            time.sleep(0.05)

    probed_all = unique_preserve_order([s for s in probed_all if s.strip()])
    write_lines(final_out, probed_all)
    return (len(gf_lines), len(filtered), len(normalized_all), len(probed_all))


def run_knoxnl(input_file: str, out_file: str, verbose: bool) -> int:
    # knoxnl -i xss -X BOTH -s -o xssoutput.txt
    args = ["knoxnl", "-i", input_file, "-X", "BOTH", "-s", "-o", out_file]
    proc = run_command(args, verbose=verbose)
    if proc.returncode != 0:
        raise RuntimeError("knoxnl failed")
    return len(read_lines(out_file))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="crawlexsses",
        description=(
            "Crawl and collect potential XSS endpoints by combining subfinder, httpx, "
            "waymore/katana/gau, gf, uro, and knoxnl. All outputs end with .txt."
        ),
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["waymore", "waymore-katana", "all"],
        default="all",
        help="History sources to use: waymore only, waymore+katana, or all (waymore+katana+gau)",
    )
    parser.add_argument(
        "-r",
        "--rate-limit",
        type=int,
        default=0,
        help=(
            "Simple IO rate limit (batch size) when streaming data into tools. "
            "0 disables chunking (default)."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    print_banner()

    domain: str = args.domain.strip()
    mode: str = args.mode
    rate: int = int(args.rate_limit or 0)
    verbose: bool = bool(args.verbose)

    # Files
    subs_file = "subs.txt"
    waymore_file = "xss-waymore.txt"
    katana_file = "xss-katana.txt"
    gau_file = "xss-gau.txt"
    merged_file = "xss.txt"
    knox_out = "xssoutput.txt"

    # Dependencies per mode
    required = ["subfinder", "httpx", "gf", "uro", "knoxnl"]
    if mode in ("waymore", "waymore-katana", "all"):
        required.append("waymore")
    if mode in ("waymore-katana", "all"):
        required.append("katana")
    if mode == "all":
        required.append("gau")

    ok, missing = ensure_tools_exist(required)
    if not ok:
        sys.stderr.write("Missing required tools: " + ", ".join(missing) + "\n")
        sys.stderr.write("Please install them and ensure they are in PATH.\n")
        sys.exit(1)

    # 1) Find subdomains and probe
    log_info(f">>> subfinder: discovering subdomains for {domain} ...")
    discovered, live = subfinder_to_httpx(domain, subs_file, rate, verbose)
    log_info(f"[✓] subfinder: {discovered} discovered; httpx live: {live}")

    # 2) History collection according to mode
    generated: List[str] = []
    if mode in ("waymore", "waymore-katana", "all"):
        log_info(">>> waymore: collecting historical URLs ...")
        waymore_count = run_waymore(subs_file, waymore_file, verbose)
        log_info(f"[✓] waymore: {waymore_count} URLs")
        generated.append(waymore_file)

    if mode in ("waymore-katana", "all"):
        log_info(">>> katana: crawling for URLs ...")
        katana_count = run_katana(subs_file, katana_file, verbose)
        log_info(f"[✓] katana: {katana_count} URLs")
        generated.append(katana_file)

    if mode == "all":
        log_info(">>> gau: fetching known URLs ...")
        gau_count = run_gau(subs_file, gau_file, rate, verbose)
        log_info(f"[✓] gau: {gau_count} URLs")
        generated.append(gau_file)

    # 3) Merge all history into xss.txt
    log_info(">>> merge: combining history into xss.txt ...")
    pre_merge_total = sum(len(read_lines(p)) for p in generated)
    merge_histories(generated, merged_file)
    merged_unique = len(read_lines(merged_file))
    log_info(f"[✓] merge: {pre_merge_total} total → {merged_unique} unique")

    # 4) Filter and probe, overwrite xss.txt
    log_info(">>> filter: gf → '=' & ext-filter → uro → httpx ...")
    gf_count, filtered_count, normalized_count, live_urls = filter_with_gf_uro_httpx(
        merged_file, merged_file, rate, verbose
    )
    log_info(
        f"[✓] filter: gf={gf_count} → '='+ext={filtered_count} → uro={normalized_count} → httpx live={live_urls}"
    )

    # 5) Run knoxnl
    log_info(">>> knoxnl: scanning for XSS ...")
    knox_count = run_knoxnl(merged_file, knox_out, verbose)
    log_info(f"[✓] knoxnl: results={knox_count} lines → {knox_out}")
    log_info("[done] Files saved:\n"
             + "\n".join([
                 f" - {subs_file}",
                 f" - {waymore_file if mode in ('waymore','waymore-katana','all') else ''}",
                 f" - {katana_file if mode in ('waymore-katana','all') else ''}",
                 f" - {gau_file if mode == 'all' else ''}",
                 f" - {merged_file}",
                 f" - {knox_out}",
             ]).strip())


if __name__ == "__main__":
    main()


