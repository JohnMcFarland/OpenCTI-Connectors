from src.labels import LabelPolicy, build_context, build_labels

from .fakes import AMBER_STRICT, RED, entity, related

OBS = "obs-1"
POLICY = LabelPolicy(
    marking_ceiling="TLP:AMBER+STRICT",
    max_labels=50,
    excluded_entity_types=frozenset(["System", "Organization", "Individual", "Incident"]),
)


def labels_for(relationships, policy=POLICY, inherited=()):
    return build_labels(build_context(OBS, relationships), inherited, policy)


def test_entities_in_both_directions_become_labels():
    result = labels_for(
        [
            related(OBS, entity("Intrusion-Set", "APT29")),
            related(OBS, entity("Malware", "Emotet"), reverse=True),
        ]
    )
    assert set(result.labels) == {"intrusion-set:APT29", "malware:Emotet"}


def test_same_name_on_two_types_stays_distinct():
    result = labels_for(
        [related(OBS, entity("Malware", "Lazarus")), related(OBS, entity("Tool", "Lazarus"))]
    )
    assert set(result.labels) == {"malware:Lazarus", "tool:Lazarus"}


def test_observables_indicators_and_containers_are_not_labels():
    neighbour = {"id": "o2", "entity_type": "Domain-Name", "parent_types": ["Stix-Cyber-Observable"]}
    indicator = entity("Indicator", "x")
    report = entity("Report", "y")
    report["parent_types"] = ["Stix-Domain-Object", "Container"]
    result = labels_for(
        [related(OBS, neighbour), related(OBS, indicator, reverse=True), related(OBS, report)]
    )
    assert result.labels == ()
    assert result.dropped == {}


def test_identity_types_are_excluded_by_default_and_counted():
    result = labels_for(
        [
            related(OBS, entity("System", "HOST-01")),
            related(OBS, entity("Individual", "A Person")),
            related(OBS, entity("Organization", "Victim Corp")),
        ]
    )
    assert result.labels == ()
    assert result.dropped == {"excluded_type": 3}


def test_exclusions_are_configurable():
    policy = LabelPolicy("TLP:AMBER+STRICT", 50, frozenset())
    result = labels_for([related(OBS, entity("Organization", "Victim Corp"))], policy)
    assert result.labels == ("organization:Victim Corp",)


def test_entity_above_ceiling_is_dropped():
    result = labels_for([related(OBS, entity("Intrusion-Set", "Secret", markings=[RED]))])
    assert result.labels == ()
    assert result.dropped == {"marking": 1}


def test_relationship_above_ceiling_is_dropped():
    # The entity is public, but the link to this observable is the secret.
    result = labels_for([related(OBS, entity("Malware", "Emotet"), markings=[RED])])
    assert result.labels == ()
    assert result.dropped == {"marking": 1}


def test_lower_ceiling_applies():
    policy = LabelPolicy("TLP:GREEN", 50, frozenset())
    result = labels_for(
        [related(OBS, entity("Malware", "Emotet", markings=[AMBER_STRICT]))], policy
    )
    assert result.labels == ()


def test_entity_with_one_permitted_path_is_kept():
    malware = entity("Malware", "Emotet")
    result = labels_for([related(OBS, malware, markings=[RED]), related(OBS, malware)])
    assert result.labels == ("malware:Emotet",)
    assert result.dropped == {}


def test_duplicates_collapse():
    malware = entity("Malware", "Emotet")
    result = labels_for([related(OBS, malware), related(OBS, malware, reverse=True)])
    assert result.labels == ("malware:Emotet",)


def test_limit_keeps_adversaries_first():
    policy = LabelPolicy("TLP:AMBER+STRICT", 2, frozenset())
    result = labels_for(
        [
            related(OBS, entity("Infrastructure", "Bulletproof")),
            related(OBS, entity("Attack-Pattern", "T1059")),
            related(OBS, entity("Malware", "Emotet")),
            related(OBS, entity("Intrusion-Set", "APT29")),
        ],
        policy,
    )
    assert result.labels == ("intrusion-set:APT29", "malware:Emotet")
    assert result.dropped == {"limit": 2}


def test_collection_requirements_pass_through_and_skip_the_limit():
    policy = LabelPolicy("TLP:AMBER+STRICT", 1, frozenset())
    result = labels_for(
        [related(OBS, entity("Malware", "Emotet"))],
        policy,
        inherited=["CR-0026: State-Nexus China", "not-a-requirement"],
    )
    assert result.labels == ("CR-0026: State-Nexus China", "malware:Emotet")


def test_unnamed_entity_is_counted_not_exported():
    result = labels_for([related(OBS, entity("Malware", ""))])
    assert result.labels == ()
    assert result.dropped == {"unnamed": 1}


def test_context_flag_follows_adversary_and_victim_types():
    adversary = build_context(OBS, [related(OBS, entity("Intrusion-Set", "APT29"))])
    victim = build_context(OBS, [related(OBS, entity("Organization", "Corp"))])
    neither = build_context(OBS, [related(OBS, entity("Attack-Pattern", "T1059"))])
    assert adversary.has_adversary_or_victim
    assert victim.has_adversary_or_victim
    assert not neither.has_adversary_or_victim
