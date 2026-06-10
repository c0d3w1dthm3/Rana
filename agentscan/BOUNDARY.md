# The Free/Paid Boundary (read before contributing)

One rule: **generic posture checks are free; working offensive content and
compliance citations are paid.**

| Goes in OSS (this repo)               | Stays PAID (private repos)                   |
|---------------------------------------|----------------------------------------------|
| Deterministic static checks (no LLM)  | LLM-driven active adversarial probes         |
| Rule format + engine + plugin seam    | The attack / eval payload corpus             |
| `maps_to: []` (empty)                 | The compliance citations that fill `maps_to` |
| Threat-modeling methodology (docs)    | Specific working attack chains               |
| Hook-coverage checks                  | Pre-built detection-hook logic               |

Why: generic posture is a commodity — give it away to win adoption. Offensive
content and compliance mapping are scarce and perishable — they ARE the business.
If a PR adds a working exploit payload or a regulatory citation to this repo, it
belongs in a paid pack instead.
