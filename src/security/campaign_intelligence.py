from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from typing import Dict, Iterable, List, Optional


@dataclass
class CampaignSummary:
    campaign_id: str
    primary_threat_label: str
    risk_level: str
    risk_score: int
    email_count: int
    first_seen: str
    last_seen: str
    top_domains: List[str] = field(default_factory=list)
    top_brands: List[str] = field(default_factory=list)
    representative_reasons: List[str] = field(default_factory=list)
    email_indices: List[int] = field(default_factory=list)
    isolated: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "primary_threat_label": self.primary_threat_label,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "email_count": self.email_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "top_domains": self.top_domains,
            "top_brands": self.top_brands,
            "representative_reasons": self.representative_reasons,
            "email_indices": self.email_indices,
            "isolated": self.isolated,
        }


class CampaignIntelligenceEngine:
    """Deterministic campaign grouping and graph/report generation."""

    def __init__(self, threshold: float = 0.38) -> None:
        self.threshold = threshold

    def similarity(self, left: Dict[str, object], right: Dict[str, object]) -> float:
        left_ind = self._indicators(left)
        right_ind = self._indicators(right)

        text_score = SequenceMatcher(
            None,
            self._text_signature(left),
            self._text_signature(right),
        ).ratio()
        domain_score = self._jaccard(left_ind.get("domains", []), right_ind.get("domains", []))
        url_score = self._jaccard(left_ind.get("urls", []), right_ind.get("urls", []))
        sender_score = 1.0 if left_ind.get("sender_domain") and left_ind.get("sender_domain") == right_ind.get("sender_domain") else 0.0
        brand_score = self._jaccard(left_ind.get("brands", []), right_ind.get("brands", []))
        qr_score = self._jaccard(left_ind.get("qr_payloads", []), right_ind.get("qr_payloads", []))
        label_score = 1.0 if left.get("Threat Label") == right.get("Threat Label") and left.get("Threat Label") else 0.0
        time_score = self._time_window_score(left_ind.get("timestamp"), right_ind.get("timestamp"))

        score = (
            0.30 * text_score
            + 0.22 * domain_score
            + 0.15 * url_score
            + 0.10 * sender_score
            + 0.10 * brand_score
            + 0.08 * qr_score
            + 0.03 * label_score
            + 0.02 * time_score
        )
        return round(score, 4)

    def cluster(self, emails: List[Dict[str, object]]) -> List[CampaignSummary]:
        suspicious = [
            (index, item)
            for index, item in enumerate(emails)
            if int(item.get("Risk Score", item.get("risk_score", 0)) or 0) >= 35
        ]
        if not suspicious:
            return []

        parent = {index: index for index, _ in suspicious}

        for i, (left_index, left) in enumerate(suspicious):
            for right_index, right in suspicious[i + 1:]:
                if self.similarity(left, right) >= self.threshold:
                    self._union(parent, left_index, right_index)

        groups: Dict[int, List[int]] = defaultdict(list)
        for index, _ in suspicious:
            groups[self._find(parent, index)].append(index)

        campaigns = []
        for number, indices in enumerate(groups.values(), start=1):
            campaigns.append(self._summarize(number, indices, emails))
        return campaigns

    def assign_campaign_ids(
        self,
        emails: List[Dict[str, object]],
        campaigns: Iterable[CampaignSummary],
    ) -> None:
        for campaign in campaigns:
            for index in campaign.email_indices:
                emails[index]["Campaign ID"] = campaign.campaign_id
                emails[index]["Campaign Risk"] = campaign.risk_level

    def graph_for_campaign(
        self,
        campaign: CampaignSummary,
        emails: List[Dict[str, object]],
        max_nodes: int = 60,
    ) -> Dict[str, object]:
        nodes: Dict[str, Dict[str, object]] = {}
        edges: List[Dict[str, str]] = []

        def add_node(node_id: str, label: str, node_type: str, weight: int = 1) -> None:
            if node_id not in nodes:
                nodes[node_id] = {"id": node_id, "label": label, "type": node_type, "weight": weight}
            else:
                nodes[node_id]["weight"] = int(nodes[node_id].get("weight", 1)) + weight

        campaign_node = f"campaign:{campaign.campaign_id}"
        add_node(campaign_node, campaign.campaign_id, "campaign", campaign.email_count)

        for index in campaign.email_indices:
            email = emails[index]
            email_node = f"email:{index + 1}"
            add_node(email_node, str(email.get("Subject") or f"Email {index + 1}")[:80], "email")
            edges.append({"source": campaign_node, "target": email_node, "relationship": "contains"})

            indicators = self._indicators(email)
            for domain in indicators.get("domains", []):
                node = f"domain:{domain}"
                add_node(node, domain, "domain")
                edges.append({"source": email_node, "target": node, "relationship": "links_to"})
            for brand in indicators.get("brands", []):
                node = f"brand:{brand}"
                add_node(node, brand, "brand")
                edges.append({"source": email_node, "target": node, "relationship": "impersonates"})
            sender_domain = indicators.get("sender_domain")
            if sender_domain:
                node = f"sender:{sender_domain}"
                add_node(node, sender_domain, "sender")
                edges.append({"source": node, "target": email_node, "relationship": "sent"})

        truncated = len(nodes) > max_nodes
        if truncated:
            kept = sorted(nodes.values(), key=lambda item: int(item.get("weight", 1)), reverse=True)[:max_nodes]
            keep_ids = {item["id"] for item in kept}
            nodes = {node_id: data for node_id, data in nodes.items() if node_id in keep_ids}
            edges = [edge for edge in edges if edge["source"] in keep_ids and edge["target"] in keep_ids]

        return {"nodes": list(nodes.values()), "edges": edges, "truncated": truncated}

    def markdown_report(
        self,
        campaign: CampaignSummary,
        emails: List[Dict[str, object]],
    ) -> str:
        related = [emails[index] for index in campaign.email_indices]
        indicators = Counter()
        for email in related:
            for domain in self._indicators(email).get("domains", []):
                indicators[domain] += 1

        lines = [
            f"# Threat Intelligence Report: {campaign.campaign_id}",
            "",
            f"- Primary threat: {campaign.primary_threat_label}",
            f"- Risk level: {campaign.risk_level}",
            f"- Risk score: {campaign.risk_score}/100",
            f"- Emails: {campaign.email_count}",
            f"- First seen: {campaign.first_seen or 'N/A'}",
            f"- Last seen: {campaign.last_seen or 'N/A'}",
            "",
            "## Top Indicators",
        ]
        if indicators:
            lines.extend(f"- {domain}: {count} email(s)" for domain, count in indicators.most_common(20))
        else:
            lines.append("- No shared domain indicator detected.")
        lines.extend(["", "## Recommended Actions"])
        lines.extend(f"- {reason}" for reason in campaign.representative_reasons[:8])
        lines.extend(["", "## Related Emails"])
        for email in related:
            lines.append(f"- {email.get('Subject', 'No subject')} | {email.get('Threat Label', 'Unknown')} | {email.get('Risk Level', 'Unknown')}")
        return "\n".join(lines)

    def reports_json(self, campaigns: Iterable[CampaignSummary]) -> str:
        return json.dumps([campaign.to_dict() for campaign in campaigns], indent=2, ensure_ascii=False)

    def _summarize(self, number: int, indices: List[int], emails: List[Dict[str, object]]) -> CampaignSummary:
        related = [emails[index] for index in indices]
        risk_scores = [int(item.get("Risk Score", item.get("risk_score", 0)) or 0) for item in related]
        labels = Counter(str(item.get("Threat Label") or item.get("threat_label") or item.get("Verdict") or "Unknown") for item in related)
        domains = Counter()
        brands = Counter()
        reasons: List[str] = []
        timestamps = []

        for item in related:
            indicators = self._indicators(item)
            domains.update(indicators.get("domains", []))
            brands.update(indicators.get("brands", []))
            timestamps.append(str(indicators.get("timestamp") or item.get("Time") or ""))
            for reason in str(item.get("Reasons", "")).split(" | "):
                if reason and reason not in reasons:
                    reasons.append(reason)

        max_score = max(risk_scores) if risk_scores else 0
        isolated = len(indices) == 1
        prefix = "ISO" if isolated else "CAMP"
        return CampaignSummary(
            campaign_id=f"{prefix}-{number:03d}",
            primary_threat_label=labels.most_common(1)[0][0],
            risk_level=self._risk_level(max_score),
            risk_score=max_score,
            email_count=len(indices),
            first_seen=min([value for value in timestamps if value], default=""),
            last_seen=max([value for value in timestamps if value], default=""),
            top_domains=[item for item, _ in domains.most_common(5)],
            top_brands=[item for item, _ in brands.most_common(5)],
            representative_reasons=reasons[:8],
            email_indices=indices,
            isolated=isolated,
        )

    def _indicators(self, email: Dict[str, object]) -> Dict[str, object]:
        indicators = email.get("Indicators") or email.get("indicators") or {}
        if isinstance(indicators, str):
            try:
                indicators = json.loads(indicators)
            except json.JSONDecodeError:
                indicators = {}
        if not isinstance(indicators, dict):
            indicators = {}

        domains = set(indicators.get("domains", []) or [])
        urls = set(indicators.get("urls", []) or [])
        for item in email.get("URLs", email.get("urls", [])) or []:
            if isinstance(item, dict):
                if item.get("domain"):
                    domains.add(str(item["domain"]))
                if item.get("final_url") or item.get("url"):
                    urls.add(str(item.get("final_url") or item.get("url")))
        return {
            "domains": sorted(domains),
            "urls": sorted(urls),
            "brands": list(indicators.get("brands", []) or []),
            "qr_payloads": list(indicators.get("qr_payloads", []) or []),
            "sender_domain": indicators.get("sender_domain") or email.get("Sender Domain", ""),
            "timestamp": indicators.get("timestamp") or email.get("Time", ""),
        }

    def _text_signature(self, email: Dict[str, object]) -> str:
        value = f"{email.get('Subject', '')} {email.get('Body', '')}".lower()
        value = re.sub(r"https?://\S+|www\.\S+", " URL ", value)
        value = re.sub(r"\W+", " ", value)
        return value[:1000]

    def _jaccard(self, left: Iterable[str], right: Iterable[str]) -> float:
        left_set = {str(item).lower() for item in left if item}
        right_set = {str(item).lower() for item in right if item}
        if not left_set or not right_set:
            return 0.0
        return len(left_set & right_set) / len(left_set | right_set)

    def _time_window_score(self, left: Optional[str], right: Optional[str]) -> float:
        left_dt = self._parse_datetime(left)
        right_dt = self._parse_datetime(right)
        if not left_dt or not right_dt:
            return 0.0
        hours = abs((left_dt - right_dt).total_seconds()) / 3600
        if hours <= 24:
            return 1.0
        if hours <= 168:
            return 0.5
        return 0.0

    def _parse_datetime(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            from email.utils import parsedate_to_datetime

            return parsedate_to_datetime(str(value)).replace(tzinfo=None)
        except Exception:
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                return None

    def _risk_level(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _find(self, parent: Dict[int, int], value: int) -> int:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def _union(self, parent: Dict[int, int], left: int, right: int) -> None:
        left_root = self._find(parent, left)
        right_root = self._find(parent, right)
        if left_root != right_root:
            parent[right_root] = left_root
