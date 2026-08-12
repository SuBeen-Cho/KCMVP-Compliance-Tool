import copy

import pytest

from experiments.final_clone_split_freeze import freeze


def _sidecar():
    return {"snapshot_id":"snapshot","sidecar_id":"sidecar","occurrences":[
        {"occurrence_id":f"o-{i}","frozen_candidate_id":f"c-{i}","group_id":f"g-{i//2}"} for i in range(265)]}


def test_split_is_deterministic_label_independent_and_group_disjoint():
    first,public=freeze(_sidecar());second,_=freeze(_sidecar())
    assert first==second and public["labels_accessed"] is False
    dev={x["group_id"] for x in first["assignments"] if x["partition"]=="development"}
    held={x["group_id"] for x in first["assignments"] if x["partition"]=="heldout"}
    assert dev.isdisjoint(held) and dev and held


def test_duplicate_identity_fails_closed():
    data=_sidecar();data[1]["occurrence_id"] if False else None
    data["occurrences"][1]["occurrence_id"]=data["occurrences"][0]["occurrence_id"]
    with pytest.raises(ValueError,match="duplicate"):freeze(data)


def test_labels_cannot_affect_assignment():
    base=_sidecar();modified=copy.deepcopy(base)
    for row in modified["occurrences"]:row["label"]="violation"
    assert freeze(base)[0]["assignments"]==freeze(modified)[0]["assignments"]
