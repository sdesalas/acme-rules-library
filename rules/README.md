# Acme Rules Library

Detection rules for Acme Corp, a fictitious company. Each rule is tuned for one business unit and one environment:
its name, tags, index patterns and, in development, its severity say which.

Rules are grouped by business unit (`corporate`, `retail`, `manufacturing`, `logistics`, `finance`, `research`,
`healthcare`, `media`), then by platform or data source, as in the Elastic prebuilt rules.

The rules are generated sample content for testing large libraries. Their index patterns point at `acme-*` indices
that do not exist, so they install but find nothing.
