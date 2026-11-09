# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 2167 | Informational (Legacy stream), current; obsoletes RFC 1714 | 1997-06 | 2026-11-09 |
| RFC 1714 | Obsolete (by RFC 2167) | 1994-11 | 2026-11-09 |
| RFC 3912 | Draft Standard, current | 2004-09 | 2026-11-09 |
| RFC 7480 | Internet Standard (STD 95), current | 2015-03 | 2026-11-09 |
| RFC 9082 | Internet Standard (STD 95); obsoletes RFC 7482 | 2021-06 | 2026-11-09 |
| RFC 9083 | Internet Standard (STD 95); obsoletes RFC 7483 | 2021-06 | 2026-11-09 |
| RFC 9224 | Internet Standard (STD 95); obsoletes RFC 7484 | 2022-03 | 2026-11-09 |
| RFC 8288 | Proposed Standard; obsoletes RFC 5988 | 2017-10 | 2026-11-09 |
| RFC 8982 | Proposed Standard (RDAP partial response) | 2021-02 | 2026-11-09 |
| RFC 9537 | Proposed Standard (RDAP redacted fields) | 2024-03 | 2026-11-09 |
| RFC 8977 | Proposed Standard (RDAP sorting and paging), not implemented | 2021-01 | 2026-11-09 |
| RFC 8521 | Best Current Practice 221 (RDAP object tagging), not implemented | 2018-11 | 2026-11-09 |
| RFC 9536 | Proposed Standard (RDAP reverse search), not implemented | 2024-04 | 2026-11-09 |
| RFC 9560 | Proposed Standard (RDAP federated authentication), not implemented | 2024-04 | 2026-11-09 |
| RFC 9877 | Proposed Standard (RDAP geofeed), not implemented | 2025-10 | 2026-11-09 |
| RFC 9910 | Proposed Standard (RDAP RIR search), not implemented | 2026-01 | 2026-11-09 |
| RFC 2606 | Best Current Practice 32; updated by RFC 6761 | 1999-06 | 2026-11-09 |
| RFC 6761 | Proposed Standard | 2013-02 | 2026-11-09 |

Known errata, checked 2026-11-09 and relevant to code here:

- **RFC 9083** has four verified errata. 7093 (section 4.1) corrects `rdapConformance` from "hints" to
  identifiers of registered specifications: it is normative, and this library treats an unknown entry as
  a fact to report, not noise. 7094 (section 2.1) changes the extension-prefix example to
  `lunarNIC_level_0`. 7340 (Appendix F) and 7986 (section 9) are editorial and example fixes.
- **RFC 9537** has one verified erratum (7876, section 4.2): the figure 13 and 14 examples give the
  `self` and `related` links the same `href`, which RFC 9083 forbids. Do not copy those examples into
  fixtures.
- **RFC 8288** has two verified errata (5319, section 1.1 and 5878, appendix B.2), neither of which
  changes the `Link` header parse this library performs.
- RFC 2167 has no errata on file. Its section numbering is not machine-segmented in rfclib's index (see
  `ROADMAP.md`, "Known gap in the local RFC index"), so directive quotes are taken from the fetched text.

Rules this file follows, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here. This project has
   one: the IANA RDAP bootstrap registry and the root zone database behind `special_names`.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')`
for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become
obligation rows.
