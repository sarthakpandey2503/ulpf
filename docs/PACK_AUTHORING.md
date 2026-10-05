# Source pack authoring

A **source pack** is a YAML file that says: how to recognize a vendor line, how to parse it, and which raw fields become which OCSF paths. Adding a vendor is a pack, not a Python change. Packs contain no `eval`, no snippets, and no shell. They are loaded with `yaml.safe_load` and checked against `ulpf/packs/schema.py`.

Library path: `ulpf/packs/library/<vendor>/<product>.yaml`. Approved AI drafts go to `data/packs/` (`ULPF_APPROVED_PACKS_DIR`). Drafts in `data/drafts/` are never routed.

## Top-level keys

`additionalProperties: false`. Unknown keys fail validation.

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | `vendor.product` style, pattern `^[a-z0-9_\-]+(\.[a-z0-9_\-]+)+$` |
| `version` | yes | Semver-ish string. AI approval bumps `0.x` to `1.0` |
| `vendor`, `product` | yes | Shown on the dashboard and in `metadata.product` |
| `match` | yes | How to decide this pack applies (all keys ANDed) |
| `parse` | yes | Ordered extractor stages |
| `classes` | yes | At least one OCSF class rule. First matching `when` wins |
| `category`, `description` | no | Documentation |
| `priority` | no | Default 50. Higher wins when several packs match |
| `tz` | no | Default timezone for timestamps |
| `provenance` | no | Free-form. `author` / `approved_by` set trust to 1.0, else 0.7 |
| `mapping` | no | Common mapping applied to every class |
| `severity_id` | no | Pack-level default severity spec |
| `tests` | no | Array, not schema-checked. Synthesized drafts store the first 3 sample lines here. Unused by the engine |

There is no `class_uid` key. The uid comes from the vendored OCSF schema via the class name.

## `match`

| Key | Meaning |
|---|---|
| `formats` | Must intersect the sniffer tags (`json`, `xml`, `cef`, `leef`, `kv`, `csv`, `syslog`, `text`) |
| `contains` | Every substring must appear in the raw line |
| `any_contains` | At least one substring |
| `regex` | RE2 search on the raw line, max 1000 characters |
| `sources` | Pin by `source_hint`. **No shipped pack sets this**, so CLI `--source` currently does nothing |

## `parse` stages

Each stage:

```yaml
- type: kv          # json | xml | csv | kv | grok | regex | cef | leef | syslog
  source: message   # parse this extracted field instead of the raw line
  prefix: sd.       # prefix keys
  required: true    # default true; failure of a required stage fails the pack
  when: { ... }     # skip the stage unless the condition holds
  # plus extractor-specific options (additionalProperties: true)
```

Extractor options used in the library:

| Type | Options |
|---|---|
| `syslog` | `sd_prefix`, `no_host`, `no_tag`. RFC 5424 structured data becomes `sd.<id>.<param>` |
| `kv` | `pair_sep` (default space), `kv_sep` (default `=`), `quote` (default `"`) |
| `csv` | `delimiter`, `quote`, `columns`, `columns_by` (`index` + `map`, key `default` supported), `keep_empty`. Column name `_skip` drops a column; extras become `_colN` |
| `json` | `flatten` (dotted keys). Enforces `MAX_FIELDS` |
| `xml` | `windows_eventdata` (Windows `<Data Name=X>` → `X`), `strip_root`. Uses defusedxml, `forbid_dtd=True` |
| `cef` / `leef` | header fields plus extensions. LEEF 1.0 and 2.0 (custom or hex delimiter) |
| `grok` / `regex` | `pattern` or `patterns`, `required`. Grok has 22 built-in patterns; compiles via RE2, cached |

## Conditions (`when`)

Used on stages, classes, and mapping specs.

- `field` plus one of `exists`, `equals`, `in`, `contains`, `startswith`, `regex`
- `equals` / `in` / `contains` / `startswith` are case-insensitive string compares
- Combine with `all: []`, `any: []`, `not: {}`
- Empty condition is always true

## Mapping specs

Three forms:

1. A string: copy that field. `None`, `""`, and `"-"` count as missing.
2. A list: coalesce, first non-empty wins.
3. An object:

| Key | Meaning |
|---|---|
| `field` | string, or list joined by `join` (default space); every field must be present |
| `const` | constant |
| `template` | `"{var}"`, every var required |
| `split` | `{sep, index}` |
| `regex` | named group `v`, else group 1, else whole match |
| `map` | case-insensitive lookup |
| `map_default_passthrough` | if the key is missing from `map`, keep the original |
| `default` | used if still empty; **bypasses** subsequent `cast` and `scale` |
| `cast` | `int`, `float`, `str`, `bool`, `ip`, `timestamp`, `lower`, `upper`, `auto` (`auto` is allowed by schema but is a no-op in the engine) |
| `format`, `tz` | timestamp parse |
| `scale` | `int(float(v) * scale)` after cast. FortiGate `duration` is seconds → OCSF milliseconds, so `scale: 1000` |
| `when` | skip this spec unless true |

Evaluation order inside `resolve`: `when` → `const` else `template` else `field` → `split` → `regex` → `map` → `default` → `cast` → `scale`. Then `apply` does OCSF type coercion and wraps scalars in a list when the attribute is an array.

Array paths use the `evidences[0].src_endpoint.ip` form (`N < 64`). Paths that do not exist on the chosen class are **silently dropped**.

## Classes

```yaml
classes:
  - name: traffic
    when: {field: type, equals: traffic}
    class: network_activity          # name, numeric uid string, or base_event
    activity_id: {field: action, map: {accept: 6, deny: 5}, default: 6}
    severity_id: { ... }             # overrides pack-level
    mapping: { ... }                 # merged on top of pack mapping
```

`activity_id` feeds `type_uid = class_uid * 100 + activity_id`.

## Worked example (FortiGate)

From [`ulpf/packs/library/fortinet/fortigate.yaml`](../ulpf/packs/library/fortinet/fortigate.yaml):

```yaml
id: fortinet.fortigate
version: "1.0"
vendor: Fortinet
product: FortiGate
priority: 60
match:
  formats: [kv]
  contains: ["devid=", "logid="]
parse:
  - {type: syslog}
  - {type: kv, source: message}
mapping:
  time:
    - {field: eventtime, cast: timestamp}
    - {field: [date, time], join: " ", cast: timestamp, format: "%Y-%m-%d %H:%M:%S"}
  device.type_id: {const: 9}
  src_endpoint.ip: srcip
  connection_info.protocol_name:
    field: proto
    map: {"6": tcp, "17": udp}
severity_id:
  field: level
  map: {critical: 5, warning: 3}
  default: 1
classes:
  - name: traffic
    when: {field: type, equals: traffic}
    class: network_activity
    activity_id:
      field: action
      map: {accept: 6, deny: 5}
      default: 6
    mapping:
      duration: {field: duration, scale: 1000}
```

`srcip=10.10.20.15` becomes `src_endpoint.ip`. `action=accept` becomes activity Traffic / disposition Allowed. Leftover vendor keys sit in `unmapped`. `raw_data` is the original line.

PAN-OS (`paloalto/panos.yaml`) is the CSV case: `columns_by.index: 3` picks TRAFFIC vs THREAT column lists, `_skip` drops unused columns, and a regex plus `map_default_passthrough` strips `(123)` suffixes from app names.

## Signing

Each library file has a sibling `<name>.yaml.sig`: base64 Ed25519 over the **exact YAML bytes**.

- Trusted public keys: `ulpf/packs/trusted/*.pub` (shipped `builtin.pub`) plus `<keys_dir>/pack_signers/*.pub`.
- `sign_pack` uses or creates `keys_dir/pack_signer.key`. Approved AI drafts are signed this way.
- `ULPF_REQUIRE_SIGNED_PACKS=true` (Compose default): unsigned or mismatched packs raise `PackError` and land in `registry.rejected`.
- Otherwise unsigned packs still load, with `ulpf.pack_signed = false`.
- Trust (`ulpf.confidence`) is 1.0 if `provenance.author` looks human or `approved_by` is set, else 0.7. **Signing is not what sets trust.**

The private key that signed the built-in packs is not part of the repository. Built-in packs verify against `builtin.pub`. Each installation creates its own `pack_signer` key on the first approval.

## Shipped packs (15, all signed)

| Pack id | File | Match / parse | OCSF classes | Sample |
|---|---|---|---|---|
| `checkpoint.cef` | `checkpoint/cef.yaml` prio 70 | cef, `\|Check Point\|`; syslog → cef | detection_finding, network_activity | `samples/perimeter/checkpoint.log` |
| `cisco.asa` | `cisco/asa.yaml` prio 60 | contains `%ASA-`; syslog → regex → grok | network_activity, authentication, detection_finding | `cisco_asa.log` |
| `fortinet.fortigate` | `fortinet/fortigate.yaml` prio 60 | kv + `devid=`,`logid=`; syslog → kv | network_activity, detection_finding, authentication | `fortigate.log` |
| `generic.cef` | `generic/cef.yaml` prio 10 | cef | network_activity | `generic_cef.log` |
| `generic.leef` | `generic/leef.yaml` prio 10 | leef | network_activity | `generic_leef.log` |
| `juniper.srx` | `juniper/srx.yaml` prio 60 | contains `RT_FLOW`; RFC5424 SD | network_activity | `juniper_srx.log` |
| `nginx.access` | `nginx/access.yaml` prio 50 | combined-log grok | http_activity | `nginx.log` |
| `openssh.sshd` | `openssh/sshd.yaml` prio 55 | contains `sshd[`; syslog → grok | authentication | `openssh.log` |
| `paloalto.panos` | `paloalto/panos.yaml` prio 60 | csv + `TRAFFIC`/`THREAT`; syslog → csv | network_activity, detection_finding | `paloalto.log` |
| `pfsense.filterlog` | `pfsense/filterlog.yaml` prio 60 | contains `filterlog`; syslog → csv | network_activity | `pfsense.log` |
| `squid.access` | `squid/access.yaml` prio 55 | epoch-time grok | http_activity | `squid.log` |
| `suricata.eve` | `suricata/eve.yaml` prio 65 | json `event_type` + IPs | detection_finding, dns, http, network | `suricata_eve.json` |
| `zeek.json` | `zeek/json.yaml` prio 65 | json `id.orig_h` or `_path` | network, dns, http, ssh, detection | `zeek.json` |
| `microsoft.windows_eventlog` | `microsoft/windows_eventlog.yaml` prio 70 | json containing `"xml"` + `<Event`; json → xml | process, network, module, file, registry, dns, authentication, account_change, win_service, scheduled_job, base_event | none (fidelity replay) |
| `sensors.canonical_alert` | `sensors/canonical_alert.yaml` prio 66 | json `event_uid` + `severity_id` | detection_finding | none (fidelity replay) |

The last two exist so the Schema Fidelity harness can parse the 551 labelled datasets (mostly Windows Event Log JSON+XML, plus flat HIDS/NIDS alerts). They are not perimeter sources.

Sophos XG and MikroTik have **no** shipped pack. They live under `samples/unknown/` and are the samples for trying the Onboard tab.

## How packs are chosen at runtime

`PackRegistry.candidates`:

1. If any pack's `match.sources` contains the source hint, only those packs are considered (unused in the library).
2. Otherwise every pack whose `CompiledPack.matches(raw, tags, source)` is true.
3. Sorted by `priority` descending.
4. First pack whose `apply()` succeeds wins. A pack that raises is skipped.

Fallback (no pack, or all packs fail) still stores the line; see [AI_PARSER_GENERATOR.md](AI_PARSER_GENERATOR.md).
