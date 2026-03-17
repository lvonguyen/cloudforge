# Wiz Security Graph — UX Reference Specification

**Source:** Wiz Operating Platform Full Demo (https://vimeo.com/805151197, 10:12 duration)
**Observed:** 2026-03-17
**Purpose:** UX pattern reference for CloudForge Security Graph implementation (F-02 / Sprint E)

---

## 1. Top-Level Navigation Architecture

### Primary Nav Bar (always visible, dark navy/blue background)
```
WIZ [All projects v] | Dashboard | Inventory | Issues | Explorer v | Policies | Compliance | Reports | Projects | [Search Cmd+K] [bell] [settings] [?] [user]
```

- "Explorer" has a chevron/dropdown (contains Security Graph, sub-sections)
- "All projects" filter is always visible in nav

### Secondary Nav Bar (appears under primary, white background, below Explorer)
```
Security Graph | Cloud Events | Vulnerabilities | Cloud Configuration Findings | Host Configuration Findings | Network Exposure
```

- Active tab underlined in blue
- "Security Graph" is the default/primary view

---

## 2. Security Graph Page — Full Layout

### 2a. Page Header
```
Security Graph                                    [New] [Save as... v] [graph-icon] [table-icon] [settings-icon]
[Edit Query]
```

- Page title "Security Graph" in large sans-serif, left-aligned
- **"Edit Query" button**: blue pill/chip with pencil icon, top-left below title
- Top-right controls:
  - **[New]** — creates a new saved query
  - **[Save as... v]** — saves current query with dropdown for save options
  - **Graph/Table toggle** — two icon buttons to switch between graph view and table/list view
  - **Settings icon** — additional options

### 2b. Left Toolbar (vertical, floating on graph canvas left edge)
```
[hierarchy icon]    <- layout toggle
[layers/stack icon] <- data layers
[photo/screenshot]  <- export
[+]                 <- zoom in
[-]                 <- zoom out
[fit-screen icon]   <- fit all nodes to viewport
```

Controls positioned vertically on left edge of the graph canvas.

### 2c. Bottom Status Bar
```
5 out of 9 results
```

Results count displayed bottom-left of the canvas.

---

## 3. Graph Visualization — Node Design

### 3a. Node Anatomy

Each node is a **circle** with:
1. **Icon inside** (service-specific icon or type icon)
2. **Primary label** below the node (resource name or identifier, e.g., "igw-62aee60a")
3. **Secondary label** below the primary (resource type, e.g., "AWS Internet Gateway")
4. Node size is **uniform** across all resource types (approximately 40-50px diameter)

### 3b. Node Color Coding by Type

| Node Type | Color | Description |
|-----------|-------|-------------|
| Internet / Entry point | Blue-green gradient (Earth globe image) | Large globe icon, shows actual Earth image, larger than other nodes |
| AWS Infrastructure (IGW, VPC, Subnet, ENI) | **Orange/amber** (#f59e0b range) | Standard AWS resource nodes |
| AWS EC2 Instance | **Blue** (medium-dark blue, hub node) | Center/target node, slightly larger ring |
| AWS IAM Role | **Purple/violet** | IAM identity nodes |
| AWS Secret Key (Secret Instance) | **Teal/cyan** (#06b6d4 range) | Key icon |
| AWS Account | **Dark blue/navy** (almost dark slate) | Cloud/account icon |
| Finding (CVE) | **Red circle with orange outline + warning triangle badge** | CVE and configuration findings |
| Configuration Finding | **Red circle with orange outline + warning triangle badge** | Same as CVE finding |
| Hosted Technology (OS, DB, server) | **Green-teal** (lime-green, distinct from IAM teal) | Technology nodes |
| Application Endpoint | **Orange** with globe/network icon | Exposed ports/services |

### 3c. Node Icons Observed

- **Internet**: Earth globe (actual planet image/emoji, large, distinctive)
- **IGW (Internet Gateway)**: building/door icon (resembles a gate)
- **VPC**: connected boxes icon (network topology)
- **VPC Subnet**: gear/settings icon
- **Network Interface (ENI)**: cloud upload icon
- **EC2 Instance**: square/VM icon (Wiz custom icon for compute)
- **IAM Role**: crown icon (signifying privilege/permissions)
- **AWS Secret Key**: key icon (padlock/key)
- **AWS Account**: cloud outline icon
- **Finding**: warning triangle (!) in red circle
- **Amazon Linux 2**: Linux/OS icon (circle with tux-like silhouette)
- **MongoDB**: leaf icon (green, MongoDB branded)
- **Apache HTTP Server**: feather/Apache icon (red)
- **Nmap**: "N" letter in circle
- **OpenSSL**: gear/lock icon (yellow-orange)
- **Application Endpoint**: globe/network icon

### 3d. Special Node Badges

- **Finding count badge**: a red circular counter badge overlaid on the top-right corner of a node (e.g., "159" in red on the EC2 node) indicating number of associated findings
- **Severity indicator**: nodes with findings can show a warning triangle overlay

---

## 4. Graph Layout Algorithm

### Layout: Hierarchical Left-to-Right (Dagre/Ranked)

The graph uses a **strict left-to-right hierarchical layout**:

```
Internet → [network path nodes] → [compute node] → [findings + technologies]
(entry)     (infrastructure)       (target/hub)     (related entities)
```

**Observed layout structure:**
```
Internet ——— IGW ——— VPC ——— Subnet ——— Network Interface ——→ EC2 Instance (hub)
                                                            /               \
                                                 IAM Role               Amazon Linux 2
                                                 Secret Key             MongoDB
                                                 CVE Finding            Apache HTTP Server
                                                 Config Finding         Nmap
                                                 AWS Account            OpenSSL
```

**Key observations:**
- Entry point (Internet) is always far **left**
- Network path flows left-to-right in a straight horizontal chain
- The "hub" resource (EC2 instance, center of attack) is placed in the **center-right**
- From the hub, related entities fan out to the **right** in a radial/spoke pattern
- Findings (CVEs, config findings) branch **below** the main horizontal path
- IAM and identity nodes connect **above** or to the side of the hub

### Edge/Connection Styles

- **Main path edges**: light gray/white thin curved lines (organic spline curves, not straight)
- **Critical path edges** (highlighted): appear as colored curves (blue/amber) when an attack path is active
- **No arrowheads visible** on most edges in the base view (directionality implied by layout position)
- Edges use smooth bezier curves, not polylines

---

## 5. Interaction Patterns

### 5a. Click a Node — Right Panel Opens

Clicking any node opens a **right-side detail panel** that slides in from the right edge, covering approximately the rightmost 25-30% of the canvas width.

**Panel header:**
```
[node-type icon]  [resource name/ID]
[close X] [scroll up] [scroll down]    ← navigation controls
[cloud provider icon: AWS | JSON | [link] [star] [share] [more...]]
```

**For resource nodes (e.g., EC2 Instance), panel shows:**
- Tags section (if any): "Name: SB" (highlighted as a key tag)
- External ID (truncated ARN)
- Provider ID
- Subscription
- Project (with count "3 Projects")
- Cloud Platform: "Amazon Web Services us-east-2"
- Gateway Type (if applicable)
- Status: `● Active` (green dot)
- Operating System: Linux
- Creation Date: (timestamp)
- Ephemeral: No
- Managed: No
- Container Host: No
- Native Type: EC2 Instance
- Addresses Open: (count)
- Wide internet exposed: Yes (with warning icon)
- vCPUs: (count)

**Bottom of panel:** Blue **"View Details >"** button (navigates to full resource detail page)

### 5b. Click a Node — Resource Detail Full Page

Navigating to the full resource page shows:

**Resource Detail Header:**
```
[resource-type icon]  [resource name / IP address]
                      [resource type: e.g., "Application Endpoint"]
[Add note] [Share Feedback] [link] [star] [share icon] [more]
```

**Tab navigation (resource-scoped):**
```
Overview | Issues | Events | Vulnerability | Configuration | Network | Identity | Secrets | Kubernetes | Application | Data
```

The active tab is underlined/highlighted. This provides deep context on a specific resource.

**Overview tab shows:**
- Key metadata (Subscription, Cloud Platform, Project count)
- Port info (Port Start, Port End, All Ports, Port Range)
- Timestamps: First seen, Last changed, Last seen
- **Dynamic Scanner Insights** section (for Application Endpoints):
  - Port Status: `△ Open` (warning triangle + status)
  - HTTP Status: 200
  - Web Page Title: (auto-detected, e.g., "Apache Tomcat/9.0.22")
  - HTTP Content Type
  - HTTP Status Code with "View Response Body" link
  - **Browser Screenshot**: embedded thumbnail showing actual webpage screenshot
- **Related Entities** section at bottom with tabular list

### 5c. Viewing Node in Context — Network Tab

When viewing a resource's Network tab within its detail page, Wiz shows a **Network Exposure Paths** mini-graph that embeds the same Security Graph visualization scoped to that resource.

Left toolbar controls for this embedded graph:
- Hierarchy/layout icon
- Export/screenshot icon
- Zoom in (+)
- Zoom out (-)
- Fit to screen icon

---

## 6. Attack Path / Toxic Combination Visualization

### 6a. Toxic Combination Overlay

When an issue represents a "toxic combination" (multiple risk factors converging), the issue detail page shows an **Evidence section** with an **inline graph card**:

```
Evidence
Overview                              [grid-icon] [table-icon] [view on graph link]
[inline mini-graph card]
```

The inline mini-graph is a **white card with rounded corners** that overlays/sits on a slightly dimmed background. It shows only the nodes relevant to the specific finding, with:
- Full attack path from Internet to target rendered inside the card
- Zoom and pan controls apply within the card
- Separate zoom level from the main graph

### 6b. Highlighted Attack Path State

The "toxic combination" graph highlight state shows:
- **Full graph visible in background** (faded/dimmed, orange node chains)
- **White card in foreground** showing the specific attack path in focus
- The specific path nodes are rendered at **higher opacity** vs background
- IAM identity nodes in the toxic path are rendered in **purple/violet**
- The hub resource node (EC2) remains in **blue** as the convergence point
- **Finding count badge** (red number, e.g., "159") shown on the hub node

### 6c. Attack Path Node Color Significance in Toxic Path

| Role in Attack | Color |
|----------------|-------|
| Entry point (Internet) | Globe (always same) |
| Network infrastructure (IGW, VPC, Subnet, ENI) | Orange (main chain) |
| Identity path (IAM Roles, service accounts) | Purple/violet |
| Secret/credential (AWS Secret Key) | Teal |
| Target resource (EC2) | Blue (hub, slightly larger or ring highlight) |
| Associated technologies | Green |
| Findings | Red with warning triangle |

---

## 7. Edit Query Interface (Graph Query Builder)

### 7a. Edit Query Button → Query Builder Panel

Clicking **"Edit Query"** opens a top-of-canvas query panel that shows the current graph query in visual form.

**Query display structure (top of graph, replaces top portion):**
```
[Query node tab 1] [x]  [+] [eye] [x]
[Hosted Tec...]  [Data]   [tab labels visible]
[Hosts]  [...]   [Patched OS]
```

The query is structured as **linked entity tabs** forming a chain/path. Each tab represents a node type in the query.

### 7b. Add Relation Dropdown (+ button)

Clicking [+] on any query node opens a **relation picker dropdown**:

```
[Search properties and relations]
─────────────────────────────────
Popular          |  Popular
Properties       |  [bug icon] Vulnerability
Application      |             that exist on it
Compute          |  [globe]  Successful HTTP GET
Configuration    |             on validated open ports
Data             |  [bug]    End of life technology
Identity         |             that runs on it
Kubernetes       |  [bug]    Unpatched OS
Management       |             that runs on it
...              |  [shield] Admin Permissions
                 |             (truncated)
                 |  [shield] High Permissions
                 |             that are assigned to it
```

**Left column**: Category navigation (with icons)
**Right column**: Relation suggestions with type + description (two-line format)
**Search bar** at top for filtering

### 7c. Query Syntax (visible from "Create Control" panel)

The graph query uses a visual query builder with this pattern:
```
FIND   [resource type]   WHERE [condition]
THAT   [relation type]   [connected resource]   WHERE [condition]
```

Example observed:
```
FIND   Virtual Machine   WHERE
       Name contains [floral-unicorn] or [SB]

THAT   Serves   Application Endpoint   WHERE
       Port Status equals [Open]   HTTP Status Code equals [200]
```

Each part is rendered as pill/chip selectors — resource types and conditions are individual pill buttons that can be clicked to change.

---

## 8. Issue Detail Panel (from Issues list)

When clicking an issue from the Issues list, a detail drawer opens:

**Header:**
```
[close X] [scroll up] [scroll down]
[issue-type icon]  [Issue Title]
                   [issue sub-type: e.g., "Excessive Access Finding"]
[Add note] [Run an action] [Create a Ticket] [Share Feedback] [link] [more...]
```

**Body fields:**
- **Description**: detailed text explanation of the risk
- **Status**: `● Open` (green dot, with dropdown)
- **Due**: "No due date" (dropdown)
- **Created**: timestamp
- **Updated**: timestamp
- **Severity**: colored pill badge — `High` (red), `Critical` (dark red), `Medium` (orange), `Low` (yellow)
- **Compliance Frameworks**: icon badges (e.g., PCI, SOC2, ISO 27001)
- **Risks**: risk category icon
- **Subscription**: cloud account name (e.g., "AWS Demo Scenarios")
- **Projects**: "3 Projects" (linked)
- **Related Tickets**: "0 Tickets" dropdown

**Evidence section** (below the metadata):
```
Evidence
Overview                              [compact icon] [table icon] [view on graph]
[inline graph or table]
```

For IAM/permission issues: shows a **Permission Suggestion** diff view:
- Left: current policy (AdministratorAccess with wildcard `"Action": ["*"]`)
- Right: suggested reduced policy (WizReduced-AdministratorAccess with specific services)
- Green highlighting on the new/added lines in the suggested policy

**Related Entities** section:
- "Is in Subscriptions: N" with "View All >" link
- Table columns: Subscription, Subscription ID, Cloud Platform, Status, Name, Native Type

---

## 9. "View on Graph" Navigation Pattern

A key interaction pattern throughout Wiz:

1. **From Inventory list**: "View on graph" button (top-right of inventory page) — opens Security Graph pre-filtered to the selected technology type
2. **From Issue detail**: "View on Graph" button/link in the Evidence section — opens Security Graph pre-filtered to show the nodes related to that specific issue
3. **From resource detail Network tab**: embedded mini-graph showing the network exposure paths for that specific resource

All "view on graph" transitions navigate to the Security Graph Explorer with the query pre-populated.

---

## 10. Node Types Inventory (Complete List Observed)

### AWS Network Infrastructure
| Node | Label Format | Color |
|------|-------------|-------|
| Internet Gateway | `igw-62aee60a / AWS Internet Gateway` | Orange |
| VPC | `vpc-32d37d59 / AWS VPC` | Orange |
| VPC Subnet | `arn:aws:ec2:us-east-2:98418.../AWS VPC Subnet` | Orange |
| Network Interface (ENI) | `arn:aws:ec2:us-east-2:98418.../AWS Network Interface` | Orange |

### AWS Compute
| Node | Label Format | Color |
|------|-------------|-------|
| EC2 Instance | `SB / AWS EC2 Instance` | Blue (hub) |

### AWS Identity
| Node | Label Format | Color |
|------|-------------|-------|
| IAM Role | `AdminAccessEc2 / AWS IAM Role` | Purple |
| IAM Role | `AcmeFuncAdmin` | Purple |
| IAM User | `wiz-exchange-user` | Purple |

### AWS Secrets
| Node | Label Format | Color |
|------|-------------|-------|
| Secret Instance | `AWS Secret Key (AccessKeyId...) / Secret Instance` | Teal/cyan |

### AWS Account
| Node | Label Format | Color |
|------|-------------|-------|
| AWS Account | `AWS Demo Scenarios / AWS Account` | Dark blue/navy |

### Findings
| Node | Label Format | Color |
|------|-------------|-------|
| CVE Finding | `CVE-2022-25235 / Finding` | Red (orange outline) |
| Configuration Finding | `EC2 Instances are not using... / Configuration Finding` | Red (orange outline) |

### Hosted Technologies (detected on EC2)
| Node | Label Format | Color |
|------|-------------|-------|
| OS | `Amazon Linux 2 (SB) / Hosted Technology` | Green |
| Database | `MongoDB (SB) / Hosted Technology` | Green |
| Web Server | `Apache HTTP Server (SB) / Hosted Technology` | Red (Apache color) |
| Scanner | `Nmap (SB) / Hosted Technology` | Green (N letter icon) |
| Crypto lib | `OpenSSL (SB) / Hosted Technology` | Yellow-orange |

### Application
| Node | Label Format | Color |
|------|-------------|-------|
| Application Endpoint | `[IP:port] / Application Endpoint` | Orange |

**Label format pattern:** `[resource-name] / [resource-type]`
- Primary label: resource name or identifier (bold, larger text)
- Secondary label: resource type (smaller, gray/lighter text, directly below)

---

## 11. UI Chrome Details

### Top-Right Controls on Security Graph Page
```
[New]  [Save as... v]  [graph-icon]  [table-icon]  [settings-icon]
```

- **New**: creates a blank new query
- **Save as...**: saves current query (dropdown likely has "Save as Control" option)
- **Graph/Table toggle**: two icons side-by-side; switching shows graph vs table view of same results
- **Settings**: gear icon for additional configuration

### Graph Canvas Controls (Floating Left Toolbar)
```
[hierarchy icon]   ← toggle layout algorithm or grouping
[layers icon]      ← toggle data layers/overlays
[camera icon]      ← export/screenshot canvas
[+]                ← zoom in
[-]                ← zoom out
[fit icon]         ← fit all to viewport (auto-zoom to show all nodes)
```

### Node Right-Click / Context Menu
Not observed in this demo. Node interactions appear limited to single-click.

---

## 12. Key Design Principles Observed

1. **Finding-scoped graph, not standalone global graph**: The Security Graph always shows results for a specific query. It's not a "map of your entire cloud" but rather "results of this graph traversal query." Every view of the graph has a query context.

2. **Left-to-right attack path direction**: Consistently renders exposure paths as Internet (left) → target resource (center) → related context (right). This mirrors how an attacker would move.

3. **Uniform node sizing with color differentiation**: All resource nodes are the same size; type is communicated through color and icon, not size. The Internet entry point is the exception (larger, distinctive).

4. **Hub-and-spoke for related entities**: The target resource (e.g., EC2) acts as a hub; all related context (hosted tech, findings, IAM) fans out as spokes to the right.

5. **Right-side detail panel on click**: Single-click a node → compact summary panel; panel has "View Details >" to navigate to full resource page. Does not require navigating away from graph.

6. **Toxic combinations shown as focus overlays**: Instead of trying to color-code the entire graph for a finding, Wiz uses a white-card overlay that isolates the relevant subgraph within the full context.

7. **Query builder is categorized and discoverable**: Relations/properties are organized into categories (Application, Compute, Configuration, Data, Identity, Kubernetes, Management, Popular). The "Popular" category surfaces the most common security-relevant traversals.

8. **Inline evidence graphs in issue details**: Issues embed a mini-graph showing the attack path, with a "View on Graph" escape hatch to the full Security Graph.

---

## 12b. Network Tab Embedded Graph (Resource-Scoped)

When viewing an individual resource's Network tab, a **"Network Exposure Paths"** mini-graph is embedded directly in the page (not in a modal/overlay):

```
Network Exposure Paths
[mini-graph viewport]
    Internet ——— [ELB] ——— [Network Interface] ——— [target resource]
[left toolbar: hierarchy, layers, screenshot, +, -]
```

**Key differences from full Security Graph:**
- Much smaller canvas (embedded in right panel, maybe 400x300px)
- Same node design/colors — identical Internet globe, orange AWS nodes
- Only shows nodes relevant to this resource's network exposure path
- Same left toolbar controls (zoom in/out, fit, export)
- The edges here appear as thin gray straight lines (not bezier curves) in the mini format

Below the mini-graph, a **"Network Exposure" table** shows:
- Columns: Accessible From, Destination IP/CDS, Port Range, Protocol, Application Endpoint
- Result count and "Configure IP Ranges" button (top-right)

---

## 13. Relevance to CloudForge (F-02 Implementation Notes)

**F-02 requirement**: Security graph embedded in finding detail Investigation tab (Wiz pattern), not standalone page of disconnected nodes.

Based on observed patterns:

1. **Embed approach**: The graph should be scoped to the finding — show the attack path for that specific finding as an inline component within the Investigation tab. This is the "Evidence" section pattern.

2. **Graph scope**: Pre-execute a query that returns nodes related to the finding (same resource → connected findings, IAM, CVEs). Do not show the global graph.

3. **Layout**: Use left-to-right hierarchical (Dagre LR algorithm). Internet/external entry on left, resource under investigation as hub in center, related context on right.

4. **Node colors**: Follow the color scheme above. Orange for AWS infrastructure, blue for EC2/compute hub, purple for IAM, teal for secrets, red for findings, green for hosted tech.

5. **Right panel**: On node click, show a compact details panel (not navigate away). Include "View Details >" as escape hatch.

6. **Attack path direction**: Render from external exposure → network path → resource → associated risks/context.

7. **Toxic combination highlight**: If multiple risk factors converge on a node, show a count badge and use the white-card focus overlay pattern (not just coloring).

8. **"View on Graph" button**: From the main finding detail, provide a link/button to the standalone Security Graph Explorer pre-filtered to this finding's context.
