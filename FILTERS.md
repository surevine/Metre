Filters
======

Filters in Metre are long-lived, stateful objects which have one instance per domain.

Currently, they only operate on inbound stanzas to a particular domain, and only on S2S
links (ie, not XEP-0114).

Filters may have global configuration, within a `<filters/>` inside the `<globals/>` section,
and must have per-domain configuration within the domain's `<filter-in/>` section. Ordering
is significant here, since filters are applied in order.

Filters may DROP, or PASS - and if they pass a stanza may have changed it.

Existing Filters
========

The only existing (working) filter is the disco-cache filter. It is a non-mutating filter which intercepts
and caches disco responses from clients (which themselves do not change) and intercepts and
responds to those disco requests to nodes it has cached.

This allows a surprising amount of redundant queries to be elided over S2S links, which can help with bandwidth management.

There is no special per-domain configuration, and no global configuration at all.

Usage:

```
<domain name='example.com'>
  <!-- ... -->
  <filter-in>
    <disco-cache/>
  </filter-in>
</domain>
```
