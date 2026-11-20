<h1><img src="acme-logo.svg" width="32" height="32"/>  Acme Rules Library</h1>

A detection rule library in git with 40,000 rules, for Acme Corp, a fictitious company. It shows a large rule source
for Elastic Security, delivered the same way as
[`detection-rules-library`](https://github.com/sdesalas/detection-rules-library): as a git repository instead of a
Fleet package. Its size is the point: it is for testing how a library of tens of thousands of rules installs, lists and
updates.

The rules are generated from the Elastic prebuilt rules and point at index patterns that do not exist. They install,
but they find nothing. They are sample content, not tested for production use.

## Layout

```
manifest.yml                         package manifest (name, version, kibana.version condition)
changelog.yml                        one entry per release
acme-logo.svg                        the package icon (the manifest's `icons`)
LICENSE.txt                          Elastic License 2.0 (`source.license: Elastic-2.0`)
rules/
  README.md                          the package description
  <business unit>/windows/<rule file name>_<environment>.json
  <business unit>/linux/...
  <business unit>/integrations/aws/...
  ...
scripts/
  generate_library.py                regenerates rules/ from detection-rules-library
```

- The package files are at the root, so the manifest, changelog and license cover everything in the library.
- Every folder under `rules/` holds rule files, and only those. The folder a rule is in says where it belongs.
- One file per rule. Its git history is its list of versions, so don't add a file per version.

## Rule files

Each file holds one rule as `{ attributes, id, type: "security-rule" }`, in JSON, in the same format as the Elastic
prebuilt rules: keys in sorted order, indented by four spaces. `id` is `<rule_id>_<version>`, and
`attributes.rule_id` and `attributes.version` are the source of truth for identity and version, not the file name.

## How the rules are generated

`scripts/generate_library.py` reads the 2,347 prebuilt rules in `detection-rules-library` at `main/v9.6.1`
(deprecated rules left out) and makes one Acme rule per business unit and environment until there are 40,000. Each
prebuilt rule gets a production and a staging variant for each of the 8 business units, and a development variant for
one or two of them, so each business unit holds about 5,000 rules. A variant changes the prebuilt rule as follows:

| Field | Change |
|---|---|
| `rule_id` | `uuid5` of the prebuilt `rule_id`, business unit and environment, so a rebuild gives the same ids |
| `version` | `1` |
| `name` | `Acme <business unit> (<environment>): <prebuilt name>` |
| `description` | a sentence naming the business unit and environment is appended |
| `author` | `Acme Security Engineering` |
| `tags` | `Acme Business Unit: …`, `Acme Environment: …` and `Source: Acme Rules Library` are added |
| `index`, `threat_index`, ES\|QL `FROM` | each pattern gets an `acme-<business unit>-<environment>-` prefix |
| `severity`, `risk_score` | one step lower in development, with `severity_mapping` and `risk_score_mapping` removed |

Everything else, including queries, MITRE mappings, investigation guides and ML job ids, is the prebuilt rule's.

| Type | Rules |
|---|---|
| eql | 17,963 |
| query | 8,755 |
| esql | 6,259 |
| new_terms | 4,557 |
| machine_learning | 1,853 |
| threshold | 511 |
| threat_match | 102 |

The largest folder holds 1,061 rules, and there are 320 folders.

```sh
python3 scripts/generate_library.py            # dry run: prints counts, writes nothing
python3 scripts/generate_library.py --apply    # rewrites the folders under rules/
```

Options: `--source <path>` (default `../detection-rules-library`), `--ref <ref>` (default `main/v9.6.1`) and
`--count <n>` (default 40,000). Python 3.9 or newer, standard library and `git` only.

## Releases

The `main` branch holds the latest release. Each release is one commit with a tag `main/v<package version>`, for
example `main/v1.0.0`, so a consumer can map a package version to a commit. A consumer can list tags to find
releases, compare the `rules/` trees of two commits to see what changed, and fetch single files without cloning.

## Using it with Kibana

Nothing in Kibana reads this repo by default. It is used to test delivering rules from a git provider, alongside the
prebuilt rules library.
