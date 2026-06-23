# Reference Verification Report

- Paper: `paper_cose.tex`
- BibTeX: `references.bib`
- Verified cite keys: **30**
- Checks:
  - DOI: Crossref metadata fetch + loose title match
  - URL: HTTP HEAD/GET reachability

## Results

| Key | DOI | Crossref | URL | Notes |
|---|---:|---:|---:|---|
| `ahmad2019blockaudit` | 10.1016/j.jnca.2019.102406 | ok | n/a |  |
| `alaba2017internet` | 10.1016/j.jnca.2017.04.002 | ok | n/a |  |
| `ali2018blockchain` | 10.1109/COMST.2018.2886932 | ok | n/a |  |
| `aumasson2013blake2` | 10.1007/978-3-642-38980-1_8 | ok | n/a |  |
| `bayer1993timestamp` | 10.1007/978-1-4613-9323-8_24 | ok | n/a |  |
| `crosby2009efficient` |   | n/a | ok (200) |  |
| `dang2015nist` | 10.6028/NIST.FIPS.180-4 | ok | n/a |  |
| `fips1403` | 10.6028/NIST.FIPS.140-3 | ok | ok (200) |  |
| `haber1991timestamp` | 10.1007/BF00196791 | ok | n/a |  |
| `hartung2016secure` |   | n/a | ok (200) |  |
| `hassan2019survey` | 10.1016/j.comnet.2018.11.025 | ok | n/a |  |
| `iso27037` |   | n/a | ok (200) |  |
| `kebande2017cloud` | 10.1080/00450618.2016.1267797 | ok | n/a |  |
| `li2017iot` | 10.1007/s10796-014-9492-7 | ok | n/a | year differs (bib 2015 vs crossref 2014) |
| `lin2017survey` | 10.1109/JIOT.2017.2683200 | ok | n/a |  |
| `ma2009new` | 10.1145/1502777.1502779 | ok | n/a |  |
| `merkle1987digital` | 10.1007/3-540-48184-2_32 | ok | n/a |  |
| `nist2020iot` |   | n/a | ok (206) |  |
| `nist80061r2` | 10.6028/NIST.SP.800-61r2 | ok | ok (200) |  |
| `nist80086` | 10.6028/NIST.SP.800-86 | ok | ok (200) |  |
| `nist80092` | 10.6028/NIST.SP.800-92 | ok | ok (200) |  |
| `pulls2015balloon` |   | n/a | ok (200) |  |
| `putz2019secure` | 10.1016/j.cose.2019.101602 | ok | n/a |  |
| `rfc5424` |   | n/a | ok (200) |  |
| `rfc7693` |   | n/a | ok (200) |  |
| `rfc9162` |   | n/a | ok (200) |  |
| `schneier1999secure` | 10.1145/317087.317089 | ok | n/a |  |
| `sinha2014continuous` | 10.1007/978-3-319-08593-7_2 | ok | n/a |  |
| `stoyanova2020survey` | 10.1109/COMST.2019.2962586 | ok | n/a |  |
| `yavuz2012efficient` | 10.1007/978-3-642-32946-3_12 | ok | n/a |  |

## Summary

- Crossref: ok=22, mismatch=0, fail=0, n/a=8.
- URL: ok=12, fail=0, n/a=18.

## Interpretation

- `ok`: Crossref/URL check succeeded.
- `mismatch`: DOI exists but Crossref title does not loosely match the BibTeX title (manual review recommended).
- `n/a`: no DOI/URL in BibTeX entry (expected for some standards or legacy venue records).

