# pe-detections-notes

This is where I turn what I actually see in Windows samples into something a
scanner or a SIEM can match. Mostly commodity loaders — the kind that drop a
copy of themselves into `%APPDATA%`, wire up an `HKCU ...\Run` key, and start
beaconing. I pull them apart statically with the sibling tool,
[pe-triage](https://github.com/runaigyuana/pe-triage), then come here and
write the detection down while the sample is still fresh in my head.

Two things I try to keep in mind while I write:

- a detection that only matches my one sample isn't a detection.
- a clean parse is not a clean binary — the strings tell you intent, not a verdict.

Everything in this repo is synthetic. The hashes are obvious placeholders, the
IPs are from the RFC 5737 documentation ranges (`203.0.113.0/24`,
`198.51.100.0/24`, `192.0.2.0/24`), and any domain is `example.com`. There is no
real family here and nothing to detonate — these are writeups, not malware.

## Writeups

- [yara-from-strings.md](yara-from-strings.md) — taking the string
  constellation off a synthetic loader (APPDATA self-copy, Run-key persistence,
  plain-HTTP beacon) and writing a YARA rule that matches the family without
  lighting up on every installer that happens to touch a Run key.
- [sigma-from-behaviour.md](sigma-from-behaviour.md) — the same loader seen from
  the endpoint-telemetry side: a process running out of AppData that writes an
  HKCU Run value, written as a Sigma rule with the false-positive tradeoffs
  spelled out instead of hidden.

## Usage

Nothing to install. Lift the YARA rule out of its writeup into a `.yar` file and
point your scanner at a directory or a memory dump; lift the Sigma rule into
your detection repo and let your backend (`sigma-cli`, or your SIEM's own
converter) compile it to a query. Read the "why" sections before you deploy
either one — the conditions are tuned on purpose, and the tuning is the whole
point.

## License

MIT
