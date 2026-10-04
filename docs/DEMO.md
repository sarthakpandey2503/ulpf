# Demo script (2 minutes)

Record the dashboard at http://127.0.0.1:8080 after `ULPF_DEMO=true .venv/bin/python -m ulpf.cli serve`. Log in as admin. Keep the terminal with `ulpf bench` ready off-camera if you want a cutaway; the spoken path below fits two minutes without it.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:15 | Live page, empty or quiet | Firewalls, proxies, and IDS boxes log in different shapes. ULPF turns each line into one OCSF event and keeps the original bytes. |
| 0:15–0:35 | Click **Load sample logs**. Point at FortiGate, Palo Alto, and Suricata rows. Open one row. | These came from different vendors. The left pane is the raw line. The right pane is the same event in OCSF. The table shows which raw field became which normalized field. |
| 0:35–1:05 | Onboard. Paste three Sophos lines from `samples/unknown/sophos_xg.log`, or generate from an unknown cluster. Show the self-test (parse rate, OCSF valid). Click **Approve and sign**. | This source had no pack. The generator drafted one offline. It does not touch live routing until an admin signs it. Adding a vendor is a YAML file, not a code change. |
| 1:05–1:25 | Fidelity page. | We replayed 551 detection datasets through this schema. Every detection the raw logs produced still fires. Mapping to native OCSF fields only lost 174 of them. The score is about detection, not just pretty JSON. |
| 1:25–1:45 | Lineage. Verify an event (all checks true). With demo mode on, tamper the stored raw text and verify again. | The ledger is a signed hash chain. Change one byte of the stored log and the proof fails. The original batch root does not move. |
| 1:45–2:00 | Hold on the failed proof, then the health of the local page. | It runs in a container, with no outbound dependency, including on an air-gapped network. |

Do not show the API token on camera. Do not tamper a real customer log; the button only exists when `ULPF_DEMO=true` and only rewrites the local demo store.
