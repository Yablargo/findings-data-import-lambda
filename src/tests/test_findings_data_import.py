#!/usr/bin/env pytest -vs
"""Tests for the findings_data_import module."""

# Standard Python Libraries
import json
from unittest.mock import MagicMock, Mock

# Third-Party Libraries
import pytest

from .. import findings_data_import as fdi

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    pytest.param("critical2", marks=pytest.mark.xfail),
)


def test_basic_validation_v1():
    """Test basic low level field validation for extract_findings."""
    with open("src/tests/artifacts/field_map.json") as fm_file:
        basic_field_map = json.load(fm_file)

    print(basic_field_map)
    valid_findings = [{"RVA ID": "RV1234", "NCATS ID": "foo", "Severity": "High"}]

    # all of the below should be invalid
    invalid_findings = [
        {"Foo": "bar"},
        {"RVA ID": "RV1234", "foo": "bar"},
        {"RVA ID": "abcdef", "NCATS ID": 1},
        {"NCATS ID": "1234", "foo": "bar"},
        None,
    ]
    # the valid finding should make it through and come out of extract_findings
    result = fdi.extract_findings(valid_findings, field_map_dict=basic_field_map)
    assert len(result) == 1

    # none of the invalid should make it through
    result = fdi.extract_findings(invalid_findings, field_map_dict=basic_field_map)
    assert len(result) == 0

    # combine both lists, and ensure only one output is received
    combined_findings = valid_findings + invalid_findings
    result = fdi.extract_findings(combined_findings, field_map_dict=basic_field_map)
    assert len(result) == 1

    # finally, test our sample json and expect 25 findings

    with open("src/tests/artifacts/expected_dhs_v1.json") as json_file:
        expected_findings = json.load(json_file)
        result = fdi.extract_findings(
            findings_data=expected_findings, field_map_dict=basic_field_map
        )

        # right now, this ingest tool ignores everything but the specific findings. Is this intentional?
        assert len(result) == 5


def test_basic_validation_v2():
    """Test basic low level field validation for extract_findings."""
    with open("src/tests/artifacts/field_map.json") as fm_file:
        basic_field_map = json.load(fm_file)

    valid_findings = {"id": "RV1234", "findings": []}

    # all of the below should be invalid
    invalid_findings = [
        {"Foo": "bar"},
        {"id": "RV1234", "foo": "bar"},
        {"RVA ID": "abcdef", "NCATS ID": 1},
        {"NCATS ID": "1234", "foo": "bar"},
        None,
    ]
    # the valid finding should make it through and come out of extract_findings
    result = fdi.extract_findings(valid_findings, field_map_dict=basic_field_map)
    assert len(result) == 1

    # none of the invalid should make it through
    for invalid_finding in invalid_findings:
        result = fdi.extract_findings(invalid_finding, field_map_dict=basic_field_map)
        assert len(result) == 0

    with open("src/tests/artifacts/expected_dhs_v2.json") as json_file:
        expected_findings = json.load(json_file)
        result = fdi.extract_findings(
            findings_data=expected_findings, field_map_dict=basic_field_map
        )

        # right now, this ingest tool ignores everything but the specific findings. Is this intentional?
        assert len(result) == 1


class FakeDB:
    """A Mock database used to determine if the correct calls are being made by findings_data_import."""


def test_database_update():
    """Test database update is called correctly against our FakeDB Mock."""
    v1_finding = {
        "Schema": "v1",
        "RVA ID": "RV1234",
        "NCATS ID": "foo",
        "Severity": "Critical",
    }
    v1_bad_finding = {"Schema": "v1", "RVA ID": "RV1234", "NCATS ID": "foo"}
    v2_finding = {"Schema": "v2", "id": "RV4444", "findings": []}
    v2_bad_finding = {"Schema": "v2", "RVA ID": "RV4444"}
    nonsense_finding = {"Peanut Butter": "Jelly"}
    fake_db = Mock()
    fake_db.findings.find_one_and_update = MagicMock(return_value=None)

    # test bad values first since they result in no calls
    with pytest.raises(ValueError):
        fdi.update_record(db=fake_db, finding=nonsense_finding)
    fake_db.findings.find_one_and_update.assert_not_called()

    with pytest.raises(ValueError):
        fdi.update_record(db=fake_db, finding=v1_bad_finding)
    fake_db.findings.find_one_and_update.assert_not_called()

    with pytest.raises(ValueError):
        fdi.update_record(db=fake_db, finding=v2_bad_finding)
    fake_db.findings.find_one_and_update.assert_not_called()

    fdi.update_record(db=fake_db, finding=v1_finding)

    fake_db.findings.find_one_and_update.assert_called_with(
        {
            "RVA ID": "RV1234",
            "NCATS ID": "foo",
            "Severity": "Critical",
        },
        {"$set": v1_finding},
        upsert=True,
    )

    # remove severity and make sure it fails
    v1_finding.pop("Severity")
    with pytest.raises(ValueError):
        fdi.update_record(db=fake_db, finding=v1_finding)

    fdi.update_record(db=fake_db, finding=v2_finding)
    fake_db.findings.find_one_and_update.assert_called_with(
        {
            "id": "RV4444",
        },
        {"$set": v2_finding},
        upsert=True,
    )

    assert "Schema" in v2_finding
    assert v2_finding["Schema"] == "v2"
