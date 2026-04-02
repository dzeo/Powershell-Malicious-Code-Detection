"""Attack pattern rule engine for PowerShell-like samples."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from psdetect.rules.taxonomy import ATTACK_PATTERN_RULES, KNOWN_RULE_CATEGORIES, KNOWN_RULE_IDS, AttackPatternRule


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    category: str
    level: int
    severity: str
    weight: float
    description: str
    mitre_techniques: list[str]
    matched_terms: list[str] = field(default_factory=list)


@dataclass
class RuleEngineResult:
    matches: list[RuleMatch]
    total_weight: float
    risk_score: float
    max_level: int
    matched_rule_ids: list[str]
    matched_categories: list[str]
    matched_techniques: list[str]


def _match_rule(rule: AttackPatternRule, text: str) -> RuleMatch | None:
    matched_terms: list[str] = []
    for pattern in rule.regexes:
        if re.search(pattern, text):
            matched_terms.append(pattern)
        elif rule.requires_all:
            return None

    if not matched_terms:
        return None

    return RuleMatch(
        rule_id=rule.rule_id,
        name=rule.name,
        category=rule.category,
        level=rule.level,
        severity=rule.severity,
        weight=rule.weight,
        description=rule.description,
        mitre_techniques=list(rule.mitre_techniques),
        matched_terms=matched_terms,
    )


def evaluate_attack_patterns(text: str) -> RuleEngineResult:
    matches: list[RuleMatch] = []
    for rule in ATTACK_PATTERN_RULES:
        match = _match_rule(rule, text)
        if match is not None:
            matches.append(match)

    total_weight = round(sum(match.weight for match in matches), 4)
    risk_score = round(min(100.0, total_weight * 10.0), 2)
    max_level = max((match.level for match in matches), default=0)
    matched_rule_ids = [match.rule_id for match in matches]
    matched_categories = sorted({match.category for match in matches})
    matched_techniques = sorted({tech for match in matches for tech in match.mitre_techniques})
    return RuleEngineResult(
        matches=matches,
        total_weight=total_weight,
        risk_score=risk_score,
        max_level=max_level,
        matched_rule_ids=matched_rule_ids,
        matched_categories=matched_categories,
        matched_techniques=matched_techniques,
    )


def rule_features(result: RuleEngineResult) -> dict[str, float]:
    matched_rule_set = set(result.matched_rule_ids)
    matched_category_set = set(result.matched_categories)
    features: dict[str, float] = {
        "rule_match_count": float(len(result.matches)),
        "rule_total_weight": float(result.total_weight),
        "rule_risk_score": float(result.risk_score),
        "rule_max_level": float(result.max_level),
    }

    for level in range(1, 5):
        features[f"rule_level_{level}_count"] = float(sum(match.level == level for match in result.matches))

    for rule_id in KNOWN_RULE_IDS:
        features[f"rule_{rule_id}"] = float(rule_id in matched_rule_set)

    for category in KNOWN_RULE_CATEGORIES:
        features[f"rule_category_{category}"] = float(category in matched_category_set)

    return features
