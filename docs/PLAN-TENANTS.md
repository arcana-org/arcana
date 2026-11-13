# Plan: a console of tenants

This plan makes Arcana's console fully tenant-based. Today a tenant is a string on a user and on a host. After this plan it is a Subscriber of the Service Provider that runs the console, in MEF 70.2's own sense. The Subscriber has its own services, users, tokens, notification channels, audit trail and directory mapping, and its services may run on the provider's shared edges. Decisions for the owner are listed at the end as **Q-n**, each with a recommendation. Steps are named **T-n.m**. There are no time estimates anywhere, only order, dependencies and risk. Markers are as in PLAN-SDN-YANG.md: **C** console, **P** page, **A** agent, **Y** YANG, **D** documents.

## What was found (main at 2d15057c)

- **A leak today, independent of the rest (fixed by T-0.1).** `guard()` (api.c) refuses `path_fleet_wide()` paths to a tenant's *session user* only. A bearer token returns from the token branch before that test is reached. A session opened by a token has an empty `s->user`, so `session_user()` is NULL. The same gap is in `l3nm_into()` (l3nm.c), vn.c, `sapnet.c:945` and `hosts.c:4166`, which all test `session_user()`. The result: an API token made by a tenant's operator reads the whole SD-WAN document (`sdwan/document`), the whole L3NM, the virtual networks and the SAPs' service-status. Writes are still held back by `touch_ok()`, which asks for operator on every edge touched. The test `authz_hosts` checks sessions only.
- **Smaller leaks.** `pfxlists_yang()` takes no request, so every signed-in user reads every prefix list. Threat-feed definitions are read by any operator, a tenant's included.
- **There is no node access table.** The rules are spread over four places: `user_path_ok()`'s `owner_only[]` and `operator_up[]`, `path_fleet_wide()` (users.c), `token_readable()` and `token_writable()` (tokens.c), and each handler's own checks. Nothing checks that a new node got a rule.
- **Rendered names are already free of collisions, provided FIBs and units stay unique.**
  - Every per-service name comes from the service's FIB: BIRD `sw<fib>` (or `sw<fib>-<jail>`), ipfw tables `sw<fib>_zone`, `_known`, `_g<n>`, `_f<n>v<n>`, `_c…`, `_zp<n>`, and the Squid, unbound, dnsmasq and Suricata instances `sw<fib>`. The IDS port is `8000+fib`.
  - Tunnel interfaces (`gre<unit>`, `wg<unit>`, `ipsec<unit>`, …) and the WireGuard port `51000+unit` come from one ledger (`unit_new()` over `st.alloc`).
  - `check_doc()` already refuses a FIB used twice across the document.
  - The only name built from a user's string is the named lists' ipfw table, `arcl_<name>` (`NLIST_TABLE`). It is unique as long as list names are unique in the document.
- **Some resources are one per edge, whatever the number of services.** On a shared edge these are the hard part:
  - the ipfw rule band `RULE_FROM` to `RULE_TO` (10–99) in set `IPFW_SET` 30;
  - the dummynet pipes, queues and nat instances from `DN_FROM` (3000), `DN_MAX` 64 of them;
  - `net.fibs`;
  - and the composite objects each edge has once: `rules`, `steer`, `bird`, `fibs`, `probes`, `ipsec`, and the dhcp, dns, proxy and IDS builds.
- **The applied-document rule (4afd489e).** `applied_l3nm` in sdwan-state.json is one snapshot. `apply_console()` and `identities_tick()` work from it. `apply_now()` and the user's apply work from what is kept.
- **The apply lock is not cluster-wide.** `apply_begin()` takes a local `flock` (`sdwan.lock`), and only the manager runs on the leader alone (`cluster_leads()`). Two nodes of a cluster can apply at the same time.
- **Cluster replication.** `replicated()` (nodes.c) carries top-level `*.json`, `runs/`, `sessions/` and `plugin-store/` only. The audit trail (`sdwan-audit.jsonl`) and the SEN and SAN files (`sdwan-*.jsonl`) are appended to each node's own data directory, so they are each node's own, not the cluster's.
- **RFC 9182 already has the Subscriber and the provider's namespace.** Its `vpn-service` has `customer-name` (from `ietf-vpn-common`'s grouping `vpn-description`: "Name of the customer that actually uses the VPN"). Its key, `vpn-id`, has "a local meaning, e.g., within a service provider network". `l3vpn-ntw/vpn-profiles` is the provider's catalogue. l3nm_mef.c does not use `customer-name` today. RFC 9731's VN and RFC 9375's PM have no customer node; both are made per `vpn-id`.
- **The agent.** `clearance()` (superbia/ynacm.c) is admin, operator or viewer, from the NACM group of the request's user. The nacm-sync puts the console's owners in group admin and the host's operators in group operator.

## 1. The tenancy model

**A tenant is a Subscriber** (MEF 70.2) of the Service Provider that runs the console. The provider is the console's untenanted principals: the owner and the provider's operators and members. Words follow MEF 70.2, Mplify 119 and MEF 138, never a vendor's.

| Object | Whose |
|---|---|
| UCSs (§12): the underlays, their tunnel kind, IPsec, MTU and MSS | the provider's |
| An edge entry (§7.8) on a provider host: its UCS End Points, relays, breakout sets, `own_table`, `bgp_import`, `transit`, NTP | the provider's |
| An edge entry on a tenant's host | the tenant's, given UCS End Points on provider UCSs it was allowed (Q-6) |
| An SWVC (§9, an L3NM `vpn-service`) and everything in it: zones, policies, flows, virtual topologies, rate limiters, security function policies and security policies (MEF 138), probes, BFD, TCA | the Subscriber named by its `customer-name`; none named, the provider's |
| An SWVC End Point (§10, a `vpn-network-access`) and its UNI (§11) | its SWVC's Subscriber, at a UNI the provider granted on a provider edge, or on a host of the Subscriber's own |
| A TVC (§7.10) and its peer, routes, UNI objects | the SWVC's Subscriber |
| Composite objects of an edge: the `rules` ruleset, `steer`, `bird`, `fibs`, `probes`, `ipsec`, dhcp, dns, proxy, IDS | the edge's owner. On a provider edge they are made of every Subscriber's part, each part from that Subscriber's own document (section 4) |
| Named lists (`arcana-l3nm` named-list) | the Subscriber named on the list; none named, the provider's |
| The allocation ledger (FIBs, RDs, units, VNIs, addresses) | the provider's. A Subscriber sees its own entries |
| `vpn-profiles` (RFC 9182's catalogue) | the provider's, read by Subscribers |
| Hosts | one tenant or none (servers.c's `tenant`, as today) |
| Users, roles, groups, tokens, invitations | the provider's, or a tenant's (section 3) |
| Workflows, runs, templates | as today, by the hosts they reach and the author's tenant |
| Prefix lists, threat feeds | the provider's or a tenant's (a `tenant` leaf) |
| Labels | the labelled host's |
| Audit trail, SENs, SANs, notification channels | one per tenant, and the provider's |

**Edges: one owner per host, shared only by grants.** A host belongs to exactly one tenant, or to none (the provider). A provider host may carry services of several Subscribers, through **grants**. A grant gives tenant T certain UNIs of provider edge E: interfaces, or VLANs on an interface. It may also give a label for how T sees E, a committed bandwidth, and a share of E's per-edge resources (rules, pipes).

On a shared edge a Subscriber has **no host role**. It cannot read the host's interfaces, routes, FIBs, ipfw, processes, logs or jobs. Through the console's views (section 6) it sees its own SWVCs, End Points, UNIs (their SAP status), TVCs and their steering and measurements, identities and audit. It may change its SWVCs, its End Points at granted UNIs, its policies, zones, flows and security policies, its named lists, its identities, the pins on its tunnels and the rekeys of its uswe tunnels. Each SWVC is in its own FIB already (D-6, a FIB per vpn-node), so the separation in the forwarding plane holds. D-6's leak, the loopback seen in every FIB, is closed on shared edges by requiring `net.add_addr_allfibs=0` there (T-3.4).

*Rejected: a host of several tenants (a list of tenants on the server).* The agent serves its host whole. A tenant viewer of such a host would read every FIB's routes, every UNI and every ipfw table, and the console cannot filter a host's own models by tenant. It would also make `user_host()` and every host page multi-tenant.

*Rejected: provider edges never shared, one edge per Subscriber.* That is not what an SD-WAN provider runs: a hub at an IXP carries many Subscribers.

**Names: the provider's namespace, global.** `vpn-id` is the single key of RFC 9182's `vpn-service` and has the provider's meaning. Arcana follows the standard. Service ids, End Point ids, UNI ids, named-list names, user names (the sign-in identifier, and the WebAuthn handle is made from it), role, group, template and workflow names stay unique across the console. Another tenant's name is refused as "taken", never said to be whose. templates.c does this already ("A name another tenant's template has is not told, nor taken"). Because names are global, rendered names cannot collide:

| Rendered | Made from | Collision across tenants |
|---|---|---|
| BIRD protocols and instances `sw<fib>`, ipfw tables `sw<fib>_*`, Squid, unbound, dnsmasq and Suricata `sw<fib>`, IDS port `8000+fib` | the SWVC's FIB, unique (`check_doc()`) and confined to the tenant's range (Q-3) | none |
| `ucs<vrf>` BIRD instances, strongSwan's `ipsec` object | the provider's edge entry | the provider's alone |
| `gre`, `gif`, `geneve`, `wg` and `ipsec<unit>`, WireGuard port `51000+unit`, VLAN units | the one ledger (`unit_new()`) | none |
| ipfw `arcl_<name>` | a named list's name, global | none |
| ipfw rule numbers 10–99, dummynet 3000+, `net.fibs` | per edge | shared: budgets (T-3.4), not names |

*Rejected: per-tenant namespaces with the tenant written into every rendered name.* `vpn-id` would have to be stored as `acme:hq` and rewritten in every view, and the BIRD, ipfw and interface name lengths would get tighter. The leak that global names cause, that a name is in use, is accepted. The page suggests a tenant prefix for new names.

**Limits per tenant** (`tenants/tenant/limits`, the provider's):
- services, End Points, identities, named lists (and their entries);
- a FIB range (`fibs/low` and `fibs/high`);
- users and tokens;
- workflows and templates;
- threat feeds;
- hosts;
- queued applies.

Per grant: bandwidth, rules and pipes. `TOKENS_MAX` (32, console-wide), `USERS_MAX` (256), `ROLES_MAX` and `GROUPS_MAX` (64) are raised, with the per-tenant limits below them.

## 2. The data model

**The L3NM: one document, the owner on each object.** `l3nm.json` stays one RFC 9182 tree. A `vpn-service` belongs to the tenant its `customer-name` names. A service with no `customer-name` is the provider's. Arcana holds the leaf to the console's tenant names: unknown, it is refused. No node of Arcana's is needed for who owns a service.

```json
{"ietf-l3vpn-ntw:l3vpn-ntw": {"vpn-services": {"vpn-service": [
  {"vpn-id": "acme-hq", "customer-name": "acme",
   "vpn-nodes": {"vpn-node": [{"vpn-node-id": "pe1", "ne-id": "pe1"}]}}]}}}
```

- *Rejected: a document per tenant (`l3nm-<n>.json`).* The planner, the cross-tenant uniqueness checks (FIB, `vpn-id`, UNI interface) and RFC 9182's single `vpn-id` key all want one tree. Per-tenant documents would need a merge on every read and a lock spanning several files.
- *Rejected: `parent-service-id`.* It points to a parent service (an L3SM, a slice request), not to a customer.

What else needs an owner is in Arcana's own augment, so a leaf there is no departure from the standard. `arcana-l3nm`'s `named-list` gets one leaf, named after `ietf-vpn-common`'s:

```yang
augment "/l3nm:l3vpn-ntw" {
  container sdwan {
    list named-list {
      leaf customer-name {
        type string;
        description
          "The Subscriber the list is of, as ietf-vpn-common's
           customer-name; none, the provider's.";
      }
    }
  }
}
```

UCSs belong to the provider. An edge entry belongs to the owner of its host (servers.c). The partition of the tree among owners is total and is written once (T-2.1).

In the MEF 70.2 document (`sdwan/document`), the provider's whole document carries `customer-name` on each SWVC, as l3nm_mef.c's table maps it (`F("customer-name", "customer-name", C)`). A Subscriber's document is its own **projection**:
- its SWVCs, without `customer-name`, which is implied;
- the UCSs it may use, id and type alone, read-only;
- its own hosts' edge entries, whole;
- each granted provider edge as `{"server": <id>, "label": <grant's label>, "unis": [...]}`, read-only;
- its named lists.

A write of a projection is merged back into the whole by owner. An element of another owner in the body is refused: 403 for an existing one, "taken" for a name.

**Versions and entity tags per scope.** `l3nm.json` keeps `"versions": {"": n, "acme": m}` beside `version`. A document PUT is checked against the writer's scope's version, so one Subscriber's save never makes another's stale (409). `restconf_precondition()` for the L3NM gets a tag per scope: the SHA-256 of the projection. Today it is `L3NM_URI` "console:l3nm" for everyone.

**`arcana-console` additions** (a new revision; SIDs added at the end of the module's range, as share/yang/SIDS.md says):

```yang
container tenants {
  description
    "The Subscribers of the Service Provider that runs this console
     (MEF 70.2): each with its hosts, its services (the L3NM's
     vpn-services whose customer-name is its name), its users,
     tokens and channels, and the UNIs of the provider's edges
     granted to it.";
  list tenant {
    key "name";
    leaf name { type name; }
    leaf number {
      type uint16 { range "1..max"; }
      config false;
      description
        "Given once, never reused: the tenant in file names and audit
         chains (a name may hold '@', which no file name may).";
    }
    leaf description { type string { length "0..200"; } }
    leaf suspended {
      type boolean;
      default false;
      description
        "Its users and tokens refused; its services stay as applied.";
    }
    container limits {
      leaf services { type uint16; }
      leaf end-points { type uint16; }
      leaf identities { type uint16; }
      leaf named-lists { type uint16; }
      leaf users { type uint16; }
      leaf tokens { type uint16; }
      leaf hosts { type uint16; }
      leaf workflows { type uint16; }
      leaf feeds { type uint16; }
      leaf applies-queued { type uint8; }
      container fibs {
        leaf low { type uint16 { range "1..max"; } }
        leaf high { type uint16 { range "1..max"; } }
        must "not(low) or not(high) or high >= low";
      }
    }
    leaf-list ucs {
      type string;
      description "The UCSs (MEF 70.2 §12) its SWVCs may list.";
    }
    list grant {
      key "edge";
      description "A provider edge's UNIs its End Points may be at.";
      leaf edge {
        type string;
        description "A provider host's id, or server/jail.";
      }
      leaf label {
        type string { length "1..64"; }
        description "What the Subscriber sees the edge as.";
      }
      list uni {
        key "interface";
        leaf interface { type string { length "1..15"; } }
        leaf-list vlan {
          type uint16 { range "1..4094"; }
          description "None: the interface untagged, whole.";
        }
      }
      leaf bandwidth { type uint64; units "bits/second"; }
      leaf rules {
        type uint8;
        description "Of the edge's ipfw band, most it may take.";
      }
      leaf pipes {
        type uint8;
        description "Of the edge's dummynet units, most it may take.";
      }
    }
    container directory {
      leaf group-base {
        type string;
        description
          "The subtree its admins may name groups under; none, they
           name none.";
      }
    }
    container notifications {
      description "As settings' of the same names, for this tenant.";
      leaf-list mail-to { type string; }
      leaf-list telegram-chats { type string; }
      leaf mail-faults { type string; }
      leaf mail-sen { type boolean; }
      leaf mail-san { type boolean; }
      leaf telegram-sen { type boolean; }
      leaf telegram-san { type boolean; }
      list mail-case { uses alert-case; }
      list telegram-case { uses alert-case; }
    }
    container sdwan {
      description
        "The provider acting in this tenant's scope: as
         arcana-console:sdwan is to the tenant's own users.";
      anydata document;
      anydata plan { config false; }
      anydata apply-state { config false; }
      action apply;
    }
    action adopt-service {
      input { leaf vpn-id { type string; mandatory true; } }
      description
        "A provider's service made this tenant's: its customer-name
         set, its applied part moved with it (section 2, migration).";
    }
  }
}
```

The `tenant` leaf of `users/user` and of `hosts/host` becomes `type leafref { path "/arcc:tenants/arcc:tenant/arcc:name"; }`. `roles/role` and `groups/group` gain the same leaf. `prefix-lists/prefix-list` and `threat-feeds/feed` gain it too.

*Rejected: a `tenants/tenant` container holding each tenant's whole stores (users, workflows, …).* Every page path would change and the console's handlers would be duplicated. *Rejected: a schema mount of `arcana-console` per tenant (RFC 8528).* It is elegant but needs machinery the console's own datastore lacks. Filtered views with a `tenant` leaf keep one path per store, as templates already do.

**Stores and files:**

| Store | Change |
|---|---|
| `users.json` | `tenant` on roles and groups |
| `tenants.json` (new, top level, replicated) | the tenants |
| `l3nm.json` | `customer-name` binding; `versions` per scope |
| `sdwan-state.json` | `alloc` and `applied` (objects by edge) stay one. `applied_l3nm`, `applied_by` and `applied_at` move to one document per scope: `sdwan-applied.json` (the provider's) and `sdwan-applied-t<number>.json`. These are top level, so the cluster carries them, and they keep the state document small (section 8) |
| `sdwan-audit.jsonl`, `sdwan-sen.jsonl`, `sdwan-san.jsonl` | stay the provider's. `…-t<number>.jsonl` hold each tenant's |
| `prefix-lists.json`, `feeds.json` | a `tenant` member on each |
| `tokens.json` | unchanged (a token's tenant is its maker's) |

**Migration, once** (pre-1.0, no compatibility kept after it). `tenants_migrate()` runs at start, or in a cluster at the first write, as `l3nm_sdwan_migrate()` does. A marker in `tenants.json` says it ran. It:
1. makes a tenant record for each distinct `tenant` string of users.json and servers.json, and each distinct `customer-name` in l3nm.json, numbered in that order;
2. moves the single `applied_l3nm` to `sdwan-applied.json`. A service already carrying a `customer-name` has its part moved to that tenant's file, so nothing kept and not applied rides along;
3. leaves every other service the provider's. Since 1b961804 a tenant's user could not touch the SD-WAN, so all of them were made by the provider. The owner hands a service to a Subscriber with `adopt-service`. That action checks that the service's edges are the tenant's hosts or granted UNIs, and moves the service's applied part with it.
4. leaves the existing `sdwan-audit.jsonl` as the provider's chain.

UPDATING.md says what happened. The migration code goes in the release after (T-8.2). *Rejected: guessing a service's tenant from its End Points' hosts.* It is wrong for any service that spans provider edges, and ambiguous for a service across two tenants' hosts.

## 3. Authorization

**Scope and level.** A principal has a scope and a level:
- **Scope:** provider (`""`), or a tenant. It is the user's `tenant`, or a token maker's, as `req_tenant()` already gives it.
- **Level:** the existing `enum crole`, read within the scope:

| Level | Provider scope | Tenant scope |
|---|---|---|
| `CROLE_OWNER` | owner: everything, the tenants among it | **tenant admin**: the tenant's users, roles, groups, invitations, tokens, notification channels and directory mapping, and (Q-4) enrolment into the tenant |
| `CROLE_OPERATOR` | provider operator: every scope's services and tools, on behalf of any Subscriber | **tenant operator**: its services, apply, workflows, templates, feeds, prefix lists |
| `CROLE_MEMBER` | provider member | **tenant viewer**: reads its scope |

`user_console()` stops capping a tenant's owner at operator. The cap and `tenant_owners()`' refusals (users.c 1351, 1720, 1828, 1918, 2134) and `users_init()`'s warning go. No deployed console has a tenant's user with an owner role (it was refused), so nothing is raised silently on upgrade. A new `user_scope()` returns the tenant. *Rejected: new enum values (`tenant-admin`, …).* `crole` is compared by order everywhere, and scope is another axis.

**Roles.**
- A role with `tenant` is that tenant's. A tenant admin makes and changes such roles. Their `host` entries may name only the tenant's hosts, and `"*"` means the tenant's hosts.
- A role with no tenant is the provider's. Its console level is read by the holder's scope, so the provider's three built-in roles still serve as templates.
- A tenant's user may hold the provider's roles or its own tenant's, never another tenant's. A group likewise.

**The node access table: new `access.c`.** It replaces `owner_only[]`, `operator_up[]`, `path_fleet_wide()`, `user_may_path()`, `token_readable()` and `token_writable()`:

```c
enum tmode { T_PROVIDER, T_VIEW, T_HOST, T_SELF };
struct access {
	const char	*path;		/* below /restconf, a prefix */
	enum crole	 read, write;	/* the least, in the principal's scope */
	enum tmode	 tenant;	/* T_PROVIDER: refused to a tenant's;
					 * T_VIEW: the handler gives its scope's view;
					 * T_HOST: by the host's role; T_SELF: one's own */
	uint8_t		 token;		/* TOK_READ | TOK_WRITE */
};
bool	access_may(const struct principal *, const char *path, bool mutate,
	    char *why, size_t len);
```

`guard()` calls `access_may()` for sessions and bearer tokens alike, which closes the leak above. The handlers that today test `session_user()` (l3nm.c, vn.c, sapnet.c, hosts.c) take the request's principal and its scope.

| Rows | read / write | Tenant mode | Token |
|---|---|---|---|
| `settings`, `ca`, `update`, `update-notes`, `cluster` | owner / owner | T_PROVIDER | none (settings), read (others) |
| `tenants` | operator / owner | T_VIEW: one's own entry. A tenant admin writes `notifications` and `directory` alone | read |
| `users`, `roles`, `groups`, invitations, `tokens` | owner / owner | T_VIEW | read, never write |
| `enrolment` | owner / owner | T_VIEW (Q-4) | none |
| `workflows`, `runs`, `templates`, `threat-feeds`, `transfers` | operator / operator | T_VIEW | read, write |
| `prefix-lists`, `labels` | member / operator | T_VIEW (prefix lists), T_HOST (labels) | read, write |
| `hosts`, `arcana-fleet:*` | member / by host role | T_HOST | read, write |
| `sdwan/*`, `ietf-l3vpn-ntw:l3vpn-ntw`, `ietf-vn:*`, `ietf-network:networks` | member / operator | T_VIEW | read, write |
| `push`, `credentials`, `plugins/plugin/store` | member / member | T_SELF | none |
| `plugins` | member / owner | T_PROVIDER for enable | read |
| `trace-path`, `wireguard-keypair` | operator | T_VIEW (hosts it may read) | read |

The check (`console_test:access_table`) walks every top-level node of `arcana-console` in the console's schema tables (`ymodel_schema`), every entry of cyang.c's `bridges[]`, and the other modules' tops the console serves, and fails where one has no row, as `make check-nacm` does for the agent.

**`principal_reach()` and `principal_host()`** keep their host logic: a tenant's user on another tenant's host, or on a provider host, has `ROLE_NONE`. Two things are added:
1. The acl snapshot (`acl_make()`) carries the tenants: suspended, grants, FIB ranges. Threads judge grants and suspension by it.
2. A new principal flag, `P_F_DELEGATED`, carries the tenant whose apply the console executes on a provider edge (section 4). `principal_reach()` grants it only on a provider host that has a grant to that tenant, and only for the sdwan-* jobs and edits the plan made. Any other request with the flag is refused.

**What stays the provider's, across tenants:**
- the tenants themselves: create, delete, limits, grants, suspension, `adopt-service`;
- UCSs and provider edge entries;
- the settings, the CA, update, the cluster, plugins;
- the directory's connection;
- `telegram_via`'s host;
- a `fresh` apply of a provider edge;
- raising `net.fibs`;
- applying every scope at once (section 4).

A provider operator may change and apply any Subscriber's services (Q-5). The change is written to that tenant's audit chain with the provider principal's name.

**Audit per tenant.** `audit_add()` gets a scope argument. Each scope is a chain of its own, under the console's one key, with its own sequence numbers: one tenant does not learn another's volume. The tenant reads its own chain, intact or broken where it breaks. The provider reads every chain, merged by time. A change that spans scopes (a provider's change of a UCS used by several tenants) is one event in the provider's chain and one in each affected tenant's. *Rejected: one chain with a tenant field.* A tenant could not verify its part without the other lines, and the sequence numbers give away activity.

## 4. Apply and the console's own work

**The applied-document rule, per scope.** What the console makes on an edge is always the **composition**:
- each scope's last-applied part (`sdwan-applied*.json`),
- except the scope being applied, whose part is taken as kept.

The new function is `l3nm_compose(kept, scope)` in l3nm.c (T-2.1):
- **A tenant's apply:** the provider's applied part, plus T's kept part, plus every other tenant's applied part.
- **The provider's apply** (`sdwan/apply`): the provider's kept part plus every tenant's applied part.
- **`apply_console()`** (identities whose time ran out, `identities_tick()`): every scope's applied part, on the edges it names alone, as 4afd489e does.
- **"Apply every scope"** (a provider's `apply` with `"scopes": "all"`): each scope's kept part, audited in each scope's chain. It is for migrations and recovery.

Because the other scopes' parts are their applied ones, a composite object on a shared edge (the `rules` ruleset, `bird`, `steer`) renders the others' lines byte for byte as before. `changes()` then finds only T's difference, so no Subscriber's pending change rides on another's apply. After the apply, `apply_begin()` writes T's kept part as T's applied part, and writes no other scope's.

**Every element has one owner.** `l3nm_partition()` gives each element of the L3NM exactly one scope. The planner's `object()` gets an `owner`:
- `tvc:`, `peer:`, `route:` and `uni:` objects are their SWVC's;
- composites are the edge owner's, with a `contributors` list.

This serves three things:
- **The plan is redacted for a tenant:** on a provider edge, its own objects whole, and composites as "changes" with no body.
- **`fresh` is scoped:** a tenant's `fresh` takes away and makes again its own objects alone. Composites are rendered again but never taken away.
- **Steps are attributed in `apply-state`.**

**The writer's rights.** `touch_ok()` (l3nm.c) and `edges_ours()` (sdwan_edge.c) are generalised:
1. The change from was to now is partitioned by scope. A tenant's principal may change only its own scope; the provider's, any.
2. Per edge, as today: operator on the host when the host is the writer's tenant's or the provider's. On a provider edge, a tenant's change is allowed where every End Point it adds or changes there is at a UNI granted to it.
3. Execution, edge by edge, in `run_main()` and `job_run()`:
   - as the applier, where the applier is an operator of the host;
   - on a provider edge granted to the applier's tenant, as the console with `P_F_DELEGATED`, the applier recorded as author;
   - anything else is refused.

**Conflicts between tenants on one edge:**
- **By name or interface:** grants are disjoint (the provider's check refuses a UNI granted twice), and `check_doc()`'s uniqueness of UNI, interface, FIB and ids is console-wide. A collision is refused at save, "taken" or "not granted to you", untold whose.
- **By resource:** the plan of the composition checks each tenant's use of the rule band, the pipes and committed bandwidth on a shared edge against its grant's budget (`rules`, `pipes`, `bandwidth`), and the whole against the edge (the existing `next >= RULE_TO`, `DN_MAX` and capacity checks). It fails as "the edge's room for … is used", naming no one. Budgets make one Subscriber's growth unable to break another's next apply (Q-8).
- **By reference:** the provider cannot remove a UCS, an edge, or a grant's UNI that any scope's kept or applied part still uses. It gets 409, naming the tenants (the provider sees them all).

**Order between tenants.** One apply at a time in the whole cluster:
- The queue `sdwan-applies` is in replicated state and is served by the leader, as the manager already is (`cluster_leads()`). The local `flock` (`sdwan.lock`) stays within a node.
- Round-robin across scopes, the provider's entries first.
- One entry per scope: an apply asked while one of the same scope waits is merged into it, since an apply applies what is kept when it starts.
- `limits/applies-queued` bounds how many a tenant may have queued.
- `rekeying` stays exclusive with applying.

*Rejected: applies of different tenants in parallel.* Composites on shared edges would race, and the composition is only sound against a fixed set of applied parts.

**Key rotation, identity expiry and steering**, each by its owner's scope:
- **Rekeys** (`rekey_tick()`, `api_sdwan_rekey()`): per tunnel. A tunnel belongs to its SWVC's tenant, so a tenant operator may rekey its own tunnels. The rotation itself stays the console's, on the composition.
- **Identities** (`api_sdwan_identities()`, `identities_tick()`): issued and revoked by the End Point's tenant. Expiry runs `apply_console()` over the composition, unchanged. The expiry notice and its audit event go to the tenant.
- **Steering pins** (`steer_pin()`): only on the pinner's own tunnels. `manager_tick()` works on the composition of applied parts, unchanged. Its results views are filtered by tunnel, then SWVC, then tenant.

## 5. Directory integration

There is one directory, the provider's (the `ldap_*` settings).
- **The mapping from a group to (tenant, role) is the role's own `tenant`.** A role with `ldap-group` and `tenant` T makes the group's members T's users with that role. The provider's roles map the provider's users. No `ldap_tenant` leaf is needed; this refines TODO.md's sketch.
- **`users_ldap_sync(name, roles, nroles)`** becomes `users_ldap_sync(name, tenant, roles, nroles)`. `roles_ldap_groups()` returns each role's tenant. The sign-in task in auth.c (around 1891 and 1989) collects the roles the user's groups give:
  - roles of one scope: the user is made or updated in that scope;
  - roles of two scopes, two tenants or a tenant and the provider: the user is refused, the log saying which groups;
  - a directory user whose scope changed: their sessions and tokens end, through the acl generation.
- **A tenant admin** may set `ldap-group` on its tenant's roles only to a DN under `tenants/tenant/directory/group-base`, for example `cn=noc,ou=acme,ou=groups,dc=example,dc=org` under `ou=acme,ou=groups,dc=example,dc=org`. That keeps a tenant from capturing the provider's staff, or from locking them out by naming their group.
- The rule against directory names that are a local user's stays.

*Rejected: a directory per tenant.* It would put connections, CAs and bind secrets in tenant hands, and the sign-in could not tell which directory to ask before knowing the user's tenant.

## 6. What each view shows per tenant

| View | A tenant sees |
|---|---|
| L3NM (`ietf-l3vpn-ntw`) | its services; the provider's `vpn-profiles` read-only; the projection of UCSs, granted edges and its own edges (section 2) |
| `sdwan/document` | its MEF 70.2 projection |
| `sdwan/plan` | its objects whole; composites on provider edges as changed or not, no body |
| `sdwan/ledger` | its own allocations |
| `sdwan/apply-state` | its applies and steps; its tunnels |
| `sdwan/steering`, `rekeys`, `identities` | its tunnels and End Points |
| `sdwan/lists` | its named lists' fetches |
| `sdwan/audit`, `sen`, `san`, `record` | its chain; its SENs and SANs; its security policies' record |
| VN (`ietf-vn`, vn.c) | the VNs of its `vpn-id`s. APs: its hosts' SAPs and its granted UNIs. Members' underlay: its tunnels' ids and states, never a provider edge's outer address (Q-9). `vn-compute` on its own members |
| SAP networks (sapnet.c) | its hosts. Granted UNIs on provider edges as SAP-only nodes, read as the console and filtered. `service-status` from its accesses alone. `sdwan/attach` only to its hosts' or granted SAPs |
| PM (vpnpm.c) | `arcana:vpn:<vpn-id>` for its services. Not `arcana:underlay`: its service links carry the figures without the underlay's supporting links |
| Hosts, fleet, events (rcstream.c's fleet stream), the socket (stream.c) | its hosts, as today |
| Service events (later, T-5.5) | its tunnels' and steering's changes on provider edges, derived by the console |
| Alerts (mail.c) | its hosts' faults, by its channels. Its services' SENs and SANs, by its channels. The provider gets everything by the provider's channels. A provider edge's host faults are the provider's alone |
| Threat feeds | its own feeds, delivered to its hosts. The provider's feeds are not listed to it |
| Prefix lists, labels | its own lists; labels of the hosts it reads |
| Map and topology | its hosts, and provider edges as opaque nodes named by the grant's label, joined by its services' tunnels, no underlay internals |

SEN routing (sen.c): `service_by_fib()` stays sound, because FIBs are unique console-wide.

## 7. The page

- **The provider's user** gets a scope picker in the top bar: "Provider (all)", then each tenant. The choice only filters the page's own lists: the provider reads everything anyway, so no server state and no header is needed. A new service or list made while a tenant is picked carries its `customer-name` or `tenant` in the body. The provider's own document and apply are at `sdwan/*`. A tenant's are at `tenants/tenant=<T>/sdwan/*`, which the SD-WAN pages use while that tenant is picked.
- **A new screen, Settings → Tenants** (`www/arcana-ui/src/tenants.c`): the list, limits, grants (an edge picker over provider hosts, its interfaces and VLANs, label, budgets), suspension, adopt-service.
- **A tenant's user.** `who_set()` already reads `tenant`. The account menu shows "acme · admin". It hides Settings except a Tenant settings tab (notifications, directory mapping), the CA, Update, Cluster, plugin enabling, and Tenants. Users, Roles, Groups and Tokens show the tenant's own.
- **SD-WAN pages for a tenant.** UCSs and granted edges read-only, granted edges by their label. Services editable. The plan shows composites on provider edges without body. The page suggests a tenant prefix for new names.
- **Map.** topo.c and glmap.c draw provider edges as opaque nodes for a tenant.

## 8. Cluster replication

- `tenants.json` and `sdwan-applied*.json` are top-level `*.json`, so `replicated()` carries them with no change. File names use the tenant's **number**, never its name, which may hold `@` (`doc_name_ok()` refuses it).
- The acl snapshot picks up another node's tenant changes at its next `acl_tick()`.
- Per-scope entity tags are made from the data, so they agree across nodes.
- The apply queue in replicated state, served by the leader, closes the existing gap that two nodes may apply at once (T-3.5).
- The audit, SEN and SAN files stay each node's own, as they are today. Per-tenant chains do not make this worse. Sending appends through the cluster log is listed as a later task in TODO.md, not done here.
- Splitting the applied snapshots out of `sdwan-state.json` keeps each `state_save()` in the apply loop from sending every tenant's L3NM again.

## 9. The agent

**Tenancy is the console's alone. No agent change.**
- On a tenant's own host, its users are NACM users as today. The nacm-sync (hosts.c `api_nacm_sync()`, `ytrans_nacm_sync()`) puts that tenant's admins with the provider's owners in group admin, and its operators in group operator.
- On a provider edge a tenant has no NACM user at all: its applies run as the console, delegated (section 4), bounded by the console's grant and owner checks and audited with the applier.
- `clearance()` stays admin, operator or viewer per host.

*Rejected: NACM groups per tenant on a shared edge, with data-node rules per FIB and interface.* The sdwan-* jobs (`sdwan-rules`, `sdwan-steer`, `sdwan-bird`) are composites that NACM cannot split. Host-wide reads (routes of every FIB, sockets, ipfw counters, processes, logs) would leak. Every module of the agent would have to know tenants.

## 10. The steps, commit by commit

Each step is one commit, bumps the console's version, and updates ARCHITECTURE.md where it changes what that file says.

### T-0
- **T-0.1 C. The tenant check for every principal.** In `guard()` (api.c), the tenant test uses `req_tenant()` for sessions, token-opened sessions and bearer tokens. `l3nm_into()`, vn.c, `sapnet.c:945` and `hosts.c:4166` take `req_principal()` and its tenant, not `session_user()`. `user_may_path()` becomes `principal_may_path()`. `pfxlists_yang(req)` stops listing lists to tenants' users until T-5.4.
  - Check: `console_test:authz_tenant_token`. A read and a write token made by acme's operator get 403 on `sdwan/document`, `l3vpn-ntw`, `ietf-vn:*`. `GET /restconf/data` has no `l3vpn-ntw`. The SAPs have no `service-status`.
  - Depends: none. Risk: low. Ship alone.

### T-1 The tenants and who may do what
- **T-1.1 C. The node access table** (access.c), replacing `owner_only[]`, `operator_up[]`, `path_fleet_wide()`, `token_readable()` and `token_writable()`, with behaviour unchanged.
  - Check: `console_test:access_table` (every node and bridge has a row). The existing `authz_*`, `tokens`, `cyang_tokens` and `console_role` cases pass unchanged.
  - Depends: T-0.1. **Risky**: every route goes through it.
- **T-1.2 C Y. Tenants** (tenants.c, tenants.json, `arcana-console`'s `tenants` with name, number, description, suspended, limits). `tenants_migrate()` part 1 (records from users and servers). The `tenant` leafrefs. The acl snapshot carries tenants. Suspension refuses sign-ins and tokens.
  - Check: `console_test:tenants`. A data directory with acme users and hosts gets tenant acme, number 1. An unknown tenant is refused. Removing a tenant that has users or hosts gives 409. Suspended: 403, its sessions end.
  - Depends: T-1.1.
- **T-1.3 C Y. Tenant roles and the tenant admin.** `tenant` on roles and groups. `user_scope()`. The cap and `tenant_owners()` go. Hosts of a tenant role are held to the tenant's. Access rows for users, roles, groups and invitations become T_VIEW.
  - Check: `console_test:authz_tenant_admin`, replacing `authz_tenant_owner`. Acme's admin invites a user into acme, makes a role whose `"*"` reaches acme's hosts alone, never sees globex's users, is refused settings, CA, update, tenants' limits and the provider's roles, and cannot give a user another tenant's role.
  - Depends: T-1.2. **Risky**: privilege semantics change.
- **T-1.4 C. Tokens per tenant.** A tenant admin lists, makes and deletes its users' tokens. `TOKENS_MAX` raised; `limits/tokens`.
  - Check: `console_test:tokens_tenant`.
  - Depends: T-1.3.
- **T-1.5 C. Directory to (tenant, role).** `roles_ldap_groups()` returns tenants. `users_ldap_sync()` takes the scope and refuses two scopes. The `group-base` rule for tenant admins.
  - Check: `console_test:ldap_tenant` with the existing test directory. A member of acme's group signs in as acme's. A member of acme's and globex's is refused saying why. Acme's admin cannot name a group outside its base.
  - Depends: T-1.3.

### T-2 Services owned
- **T-2.1 C Y. The partition.** `l3nm_partition()` and `l3nm_compose()` (l3nm.c, or a new `l3nm_owner.c`). `customer-name` is held to tenant names. `arcana-l3nm`'s `named-list/customer-name` (new revision, .sid). No behaviour change yet.
  - Check: `console_test:l3nm_partition`. For every L3NM fixture of `l3nm_mef` and `sdwan_*`, compose(partition(x)) = x, and each element has one owner.
  - Depends: T-1.2.
- **T-2.2 C Y. Grants and the tenants' UCSs.** `tenants/tenant/grant` and `ucs`. The provider's checks: no UNI granted twice, no grant on a tenant's host, no removal in use.
  - Check: `console_test:tenant_grants`.
  - Depends: T-2.1.
- **T-2.3 C. Scoped L3NM and document.** `api_l3nm()`, `l3nm_sdwan_put()` and `api_sdwan()` give and take a scope's projection. Versions and tags per scope. Limits checked (services, End Points, identities, lists, FIB range). `tenants/tenant=<T>/sdwan/document` for the provider. The access rows lift the tenant refusal for these paths.
  - Check: `console_test:l3nm_tenant`. Acme PUTs its service through `l3vpn-ntw` and through the MEF document. Its GET has nothing of globex's. A `vpn-id` of globex's: 409 "taken". Acme's tag is unchanged by globex's save. An End Point at an ungranted UNI: 403. A FIB outside the range: 400.
  - Depends: T-2.1, T-2.2. **Risky**: the merge of a projection back into the whole.
- **T-2.4 C. Migration parts 2 and 3** (applied snapshot to the provider, `customer-name`s to their tenants) and `adopt-service`.
  - Check: `console_test:tenants_migrate_sdwan`. A data directory with one `applied_l3nm` and a service with `customer-name` acme comes up with two snapshot files. A plan right after migration makes nothing. Adopting a service makes no change on the edges.
  - Depends: T-2.3, T-3.1 (the snapshot files).

### T-3 Apply
- **T-3.1 C. Applied parts per scope.** `sdwan-applied*.json`. `apply_begin()`, `apply_now()` and `apply_console()` on `l3nm_compose()`. `applied_l3nm()` and `applied_doc()` per scope.
  - Check: `console_test:sdwan_apply_scoped`, with the stand-in agents of `sdwan_apply`. Provider edge pe1, acme and globex each with a service on it. Acme keeps a change, globex applies, and pe1 gets nothing of acme's. Acme applies, and pe1's `rules` differ only in acme's lines. `identities_tick()` takes away an expired identity of globex's without acme's kept change.
  - Depends: T-2.3. **Risky**: the core of the apply.
- **T-3.2 C. Owners of planned objects.** `object()` gets an owner; composites get contributors. The plan is redacted for tenants. `fresh` is scoped.
  - Check: `console_test:sdwan_plan_tenant`. Acme's plan shows pe1's `rules` as changed with no body. Acme's `fresh` takes away its `tvc:` and `uni:` objects alone.
  - Depends: T-3.1. **Risky**: it touches every builder of sdwan_edge.c.
- **T-3.3 C. Delegated execution on provider edges.** `edges_ours()` and `touch_ok()` with grants. `P_F_DELEGATED` in `principal_reach()`. `run_main()` and `job_run()` choose the acting principal per edge.
  - Check: `console_test:sdwan_delegated`. Acme's operator, with no role on pe1, applies there. Its own RESTCONF read of pe1 is 403. A delegated principal asking pe1 for anything but the plan's jobs is refused. The audit line names the operator.
  - Depends: T-3.1. **Risky**: a new way the console acts for no host role.
- **T-3.4 C. Shared-edge budgets and isolation.** Grant budgets for rules, pipes and bandwidth in the plan. `plan_needs()` requires `net.add_addr_allfibs=0` on an edge with grants.
  - Check: `console_test:sdwan_shared_isolation`. Every rule line contributed by acme names only acme's UNIs, tables and FIB, and the same for globex. A budget exceeded fails acme's plan without naming globex.
  - Depends: T-3.2.
- **T-3.5 C. One apply in the cluster.** The queue in replicated state, served by the leader. Round-robin. `applies-queued`.
  - Check: `raft_test` or `console_test:cluster_apply_serial`. Two nodes asked to apply at once: one runs, the other runs after. The same scope asked twice: merged.
  - Depends: T-3.1. **Risky**: cluster behaviour.
- **T-3.6 C. Scoped verbs and reads.** Steering, pins, rekeys, identities, ledger, apply-state, lists and record, each by owner.
  - Check: `console_test:sdwan_tenant_views`.
  - Depends: T-3.2.

### T-4 Views
- **T-4.1 C. VN per scope** (vn.c), and `vn-compute`.
  - Check: `console_test:l3nm_vn_tenant`.
  - Depends: T-2.3.
- **T-4.2 C. SAP networks per scope** (sapnet.c), granted UNIs as SAPs, `sdwan/attach` limited to them.
  - Check: `console_test:sapnet_tenant`.
  - Depends: T-2.2, T-2.3.
- **T-4.3 C. PM per scope** (vpnpm.c).
  - Check: `console_test:sdwan_vpn_pm_tenant`.
  - Depends: T-2.3.

### T-5 Records, channels, the rest of the stores
- **T-5.1 C. Audit chains per scope** (audit.c `audit_add(scope, …)`, `api_sdwan_audit()`).
  - Check: `console_test:sdwan_audit_tenant`. Each chain is intact on its own. Sequence numbers are per tenant. One line altered in acme's chain breaks acme's alone.
  - Depends: T-2.3.
- **T-5.2 C. SEN and SAN per scope** (sen.c), told by the tenant's channels.
  - Check: `console_test:sdwan_notices_tenant`.
  - Depends: T-5.1, T-5.3.
- **T-5.3 C Y. Tenant channels** (`tenants/tenant/notifications`). mail.c routes the faults of a tenant's hosts to the tenant and the provider. A tenant never sees `telegram_via`'s host named.
  - Check: `console_test:mail_tenant`.
  - Depends: T-1.3.
- **T-5.4 C Y. Prefix lists, threat feeds and labels per scope** (prefixlists.c, feeds.c, labels.c; the `tenant` leaves). A tenant's feeds go to its hosts alone.
  - Check: `console_test:pfx_tenant`, `feeds_tenant`.
  - Depends: T-1.3.
- **T-5.5 C. Service events for a tenant** (rcstream.c, a derived source): its tunnels and steering on provider edges.
  - Check: `console_test:authz_stream_tenant`.
  - Depends: T-3.6. Optional.

### T-6 The page
- **T-6.1 P. The scope picker and the Tenants screen** (`src/tenants.c`, `app.h`, `actions.c`, `main.c`).
  - Check: `pwa_test:tenants_admin`.
  - Depends: T-2.2.
- **T-6.2 P. A tenant's page** (`src/users.c`, `src/sdwan.c`): hidden screens, projections, labels of granted edges.
  - Check: `pwa_test:tenant_page`. Acme's admin sees Users, Tokens, Services and Tenant settings; no Settings, CA, Update or Cluster. Its SD-WAN page shows pe1 by its label, read-only.
  - Depends: T-2.3, T-1.3.
- **T-6.3 P. The map per tenant** (`topo.c`, `glmap.c`).
  - Check: `pwa_test:tenant_map`.
  - Depends: T-4.1.

### T-7 Hosts of a tenant
- **T-7.1 C. Enrolment into a tenant** (pki.c's tokens carry the tenant; `limits/hosts`).
  - Check: `console_test:enrol_tenant`.
  - Depends: T-1.3, Q-4.
- **T-7.2 C. nacm-sync with tenant admins** (hosts.c, ytrans.c).
  - Check: `console_test:nacm_sync_tenant`. Acme's host's group admin lists the provider's owners and acme's admins.
  - Depends: T-1.3. **A** unchanged.

### T-8 Documents
- **T-8.1 D.** ARCHITECTURE.md (Authentication's tenants, "Whom for", the access table); TODO.md (the two Authorization items closed, the shared audit across a cluster noted); UPDATING.md (the migration); the book.
  - Depends: T-6.2.
- **T-8.2 C.** The migration code removed, in the release after T-8.1.

### Order

| Group | Needs | Delivers |
|---|---|---|
| T-0 | none | the token leak closed |
| T-1 | T-0 | tenants, the access table, tenant admins, tokens, directory |
| T-2 | T-1.2 | services owned, grants, projections, migration |
| T-3 | T-2.3 | per-scope apply, delegation, budgets, cluster serialization |
| T-4 | T-2.3 | VN, SAP and PM per scope |
| T-5 | T-1.3, T-2.3 | audit, SEN, SAN, channels, lists, feeds |
| T-6 | T-2, T-1.3 | the page |
| T-7 | T-1.3 | enrolment, nacm-sync |
| T-8 | all | documents, the migration removed |

T-4 and T-5 can run beside T-3. T-2.4 waits on T-3.1.

### Risks
- **T-3.1 and T-3.2:** the composition and the owner of each planned object. A wrong owner leaks or drops a Subscriber's objects on a shared edge. `l3nm_partition()`'s total-partition check and T-3.4's isolation check are the guards.
- **T-3.3:** delegated execution is a new way the console acts on a host where the requester has no role. It is held to the plan's own jobs and edits, on granted edges, and audited.
- **T-1.1 and T-1.3:** every route's authorization moves at once. The existing authz suite must pass unchanged at T-1.1, before any semantics change at T-1.3.
- **T-2.3:** merging a projection back into the whole. A tenant's PUT must never delete what it cannot see. The merge is by owner, never "replace the tree".
- **T-3.5:** the apply moving to the leader changes where applies run in a cluster.
- **Shared-edge limits:** one ipfw band (90 rules) and 64 dummynet units per edge bound how many Subscribers an edge can carry before the bands are widened.
- **IDS port:** `IDS_PORT(fib)` is `8000+fib`, so FIB ranges above 57535 overflow it. FIB ranges are held below that until the IDS port is allocated from the ledger.

## Questions for the owner

- **Q-1 Sharing.** A provider host is shared by grants, and a tenant's host is the tenant's alone. **Recommended.** Rejected: hosts of several tenants (section 1).
- **Q-2 Names.** One global namespace, collisions refused as "taken", per RFC 9182's provider-scoped `vpn-id`. **Recommended.** Rejected: per-tenant namespaces.
- **Q-3 FIBs.** A console-wide unique FIB per service, within a range per tenant, keeping every rendered name and `service_by_fib()` as they are. **Recommended now.** The cost: `net.fibs` on a shared edge rises to the highest range. Later: per-node FIBs (`fib:VPN/NODE`, already in l3nm_plan.c) to keep `net.fibs` small, with rendered names and SEN lookups keyed by edge and FIB.
- **Q-4 Enrolment.** May a tenant admin enrol hosts into its tenant? **Recommended: yes**, under `limits/hosts`, the host's tenant forced.
- **Q-5 The provider on a Subscriber's services.** Always allowed and written in the tenant's chain, or only for "provider-managed" tenants? **Recommended: always**, visible to the tenant.
- **Q-6 UCSs.** The provider's alone, or may a Subscriber define its own (its own circuits at its own hosts)? **Recommended: the provider's alone for now.** A tenant's hosts have UCS End Points on UCSs listed in `tenants/tenant/ucs`.
- **Q-7 Directory.** One directory, tenant mappings under a delegated `group-base`. **Recommended.** Rejected: a directory per tenant.
- **Q-8 Shared resources.** Budgets per grant (rules, pipes, bandwidth) set by the provider, or first come? **Recommended: budgets.** First come lets one Subscriber's growth fail another's next apply.
- **Q-9 Provider addresses.** Do tenants see a provider edge's WAN and outer tunnel addresses? **Recommended: no.** Ids and states only.
- **Q-10 Audit.** A chain per tenant, or one chain with a tenant field? **Recommended: per tenant.**
- **Q-11 Fairness.** One apply at a time in the cluster, round-robin by scope, the provider first. **Recommended.** Rejected: parallel applies.
- **Q-12 Migration.** Existing services stay the provider's until adopted, except those already naming a `customer-name`. **Recommended.**
- **Q-13 Roles.** May tenant users keep holding the provider's roles, read in their scope, beside their tenant's own? **Recommended: yes.** No role migration is needed, and the built-in roles serve as templates.
- **Q-14 Suspension.** A suspended tenant's users and tokens are refused and its services stay as applied. Or are they also taken down? **Recommended: refused, services kept.** Taking them down is an explicit provider apply.
- **Q-15 T-0.1 first.** Ship it on its own, ahead of the rest. **Recommended.**
- **Q-16 Isolation sysctl.** Require `net.add_addr_allfibs=0` on any edge with grants (a plan need, refused until set)? **Recommended: yes**, per D-6's own caveat.
