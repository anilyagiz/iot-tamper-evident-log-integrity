import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PAPER = ROOT / "paper_cose.tex"
BIB = ROOT / "references.bib"
OUT = ROOT / "reference_verification_report.md"


UA = "iot-tamper-evident-log-integrity/verify_references (mailto:example@example.com)"


def _norm_title(s: str) -> str:
    # Keep it simple: strip LaTeX-ish braces and punctuation, collapse whitespace.
    s = re.sub(r"[{}\\\\]", " ", s)
    s = re.sub(r"[^a-zA-Z0-9]+", " ", s).strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _extract_cite_keys(tex: str) -> list[str]:
    keys: set[str] = set()
    for m in re.finditer(r"\\cite[a-zA-Z\*]*\{([^}]+)\}", tex):
        for k in m.group(1).split(","):
            k = k.strip()
            if k:
                keys.add(k)
    return sorted(keys)


@dataclass
class BibEntry:
    key: str
    entry_type: str
    raw: str
    title: str | None
    year: str | None
    doi: str | None
    url: str | None


def _parse_bib(bib: str) -> dict[str, BibEntry]:
    entries: dict[str, BibEntry] = {}
    # Naive BibTeX splitting: good enough for this repo's file.
    chunks = re.split(r"\n(?=@\w+\{)", "\n" + bib.strip() + "\n")
    for ch in chunks:
        ch = ch.strip()
        if not ch.startswith("@"):
            continue
        m = re.match(r"@(\w+)\{\s*([^,\s]+)\s*,", ch, re.DOTALL)
        if not m:
            continue
        entry_type, key = m.group(1), m.group(2)

        def field(name: str) -> str | None:
            fm = re.search(rf"^\s*{re.escape(name)}\s*=\s*\{{(.*?)\}}\s*,?\s*$", ch, re.MULTILINE | re.DOTALL)
            if fm:
                return fm.group(1).strip()
            fm = re.search(rf"^\s*{re.escape(name)}\s*=\s*\"(.*?)\"\s*,?\s*$", ch, re.MULTILINE | re.DOTALL)
            if fm:
                return fm.group(1).strip()
            return None

        entries[key] = BibEntry(
            key=key,
            entry_type=entry_type,
            raw=ch,
            title=field("title"),
            year=field("year"),
            doi=(field("doi") or None),
            url=(field("url") or None),
        )
    return entries


def _http_head_or_get(url: str, timeout_s: int = 20) -> tuple[int | None, str | None]:
    # Some hosts reject HEAD; fall back to a tiny GET.
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, None
    except Exception:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA, "Range": "bytes=0-512"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return resp.status, None
        except urllib.error.HTTPError as e:
            return e.code, str(e)
        except Exception as e:
            return None, str(e)


def _crossref_lookup(doi: str, timeout_s: int = 20) -> tuple[dict | None, str | None]:
    doi = doi.strip()
    # Crossref wants lowercase in URL path for some DOIs.
    url = "https://api.crossref.org/works/" + urllib.parse.quote(doi.lower(), safe="")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return payload.get("message"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)


def main() -> int:
    tex = PAPER.read_text(encoding="utf-8")
    bib_text = BIB.read_text(encoding="utf-8")
    cite_keys = _extract_cite_keys(tex)
    bib = _parse_bib(bib_text)

    missing = [k for k in cite_keys if k not in bib]
    if missing:
        OUT.write_text(
            "# Reference Verification Report\n\n"
            "BibTeX is missing the following cite keys:\n\n"
            + "\n".join(f"- `{k}`" for k in missing)
            + "\n",
            encoding="utf-8",
        )
        return 2

    lines: list[str] = []
    lines.append("# Reference Verification Report")
    lines.append("")
    lines.append(f"- Paper: `{PAPER.name}`")
    lines.append(f"- BibTeX: `{BIB.name}`")
    lines.append(f"- Verified cite keys: **{len(cite_keys)}**")
    lines.append("- Checks:")
    lines.append("  - DOI: Crossref metadata fetch + loose title match")
    lines.append("  - URL: HTTP HEAD/GET reachability")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| Key | DOI | Crossref | URL | Notes |")
    lines.append("|---|---:|---:|---:|---|")

    counts = {
        "crossref_ok": 0,
        "crossref_mismatch": 0,
        "crossref_fail": 0,
        "crossref_na": 0,
        "url_ok": 0,
        "url_fail": 0,
        "url_na": 0,
    }

    # Be a good citizen: small delay between Crossref calls.
    last_call = 0.0

    for k in cite_keys:
        e = bib[k]
        doi = (e.doi or "").strip()
        url = (e.url or "").strip()
        doi_ok = ""
        url_ok = ""
        notes: list[str] = []

        if doi:
            # rate-limit to ~3 req/s
            now = time.time()
            sleep_s = max(0.0, (last_call + 0.35) - now)
            if sleep_s > 0:
                time.sleep(sleep_s)
            last_call = time.time()

            msg, err = _crossref_lookup(doi)
            if err:
                doi_ok = f"fail ({err})"
                counts["crossref_fail"] += 1
            elif not msg:
                doi_ok = "fail (no message)"
                counts["crossref_fail"] += 1
            else:
                cr_title = (msg.get("title") or [""])[0]
                cr_year = None
                # issued/date-parts is most common
                try:
                    cr_year = str(msg.get("issued", {}).get("date-parts", [[None]])[0][0])
                except Exception:
                    cr_year = None
                bib_title = e.title or ""
                if _norm_title(cr_title) and _norm_title(bib_title):
                    nt1 = _norm_title(cr_title)
                    nt2 = _norm_title(bib_title)
                    if nt1 == nt2 or nt1 in nt2 or nt2 in nt1:
                        doi_ok = "ok"
                        counts["crossref_ok"] += 1
                    else:
                        doi_ok = "mismatch"
                        notes.append(f"title differs (crossref: {cr_title})")
                        counts["crossref_mismatch"] += 1
                else:
                    doi_ok = "ok"
                    counts["crossref_ok"] += 1
                if e.year and cr_year and cr_year != "None" and e.year != cr_year:
                    notes.append(f"year differs (bib {e.year} vs crossref {cr_year})")
        else:
            doi_ok = "n/a"
            counts["crossref_na"] += 1

        if url:
            status, err = _http_head_or_get(url)
            if status and 200 <= status < 400:
                url_ok = f"ok ({status})"
                counts["url_ok"] += 1
            elif status:
                url_ok = f"fail ({status})"
                if err:
                    notes.append(err)
                counts["url_fail"] += 1
            else:
                url_ok = "fail"
                if err:
                    notes.append(err)
                counts["url_fail"] += 1
        else:
            url_ok = "n/a"
            counts["url_na"] += 1

        doi_disp = doi if doi else ""
        notes_disp = "; ".join(notes)
        lines.append(f"| `{k}` | {doi_disp or ' '} | {doi_ok} | {url_ok} | {notes_disp} |")

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Crossref: ok={counts['crossref_ok']}, mismatch={counts['crossref_mismatch']}, fail={counts['crossref_fail']}, n/a={counts['crossref_na']}.")
    lines.append(f"- URL: ok={counts['url_ok']}, fail={counts['url_fail']}, n/a={counts['url_na']}.")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("- `ok`: Crossref/URL check succeeded.")
    lines.append("- `mismatch`: DOI exists but Crossref title does not loosely match the BibTeX title (manual review recommended).")
    lines.append("- `n/a`: no DOI/URL in BibTeX entry (expected for some standards or legacy venue records).")
    lines.append("")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
