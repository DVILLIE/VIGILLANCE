"""Response-contract fixtures, not vulnerability evidence about the host."""
import pytest
from agent.assessment.dependencies import parse_results

PACKAGES = [{"name": "package-under-test", "version": "1.0"}]


@pytest.mark.parametrize("payload", [None, {}, {"results": []}, {"results": [None]},
    {"results": [{"next_page_token": "more"}]}, {"results": [{"vulns": "invalid"}]},
    {"results": [{"vulns": [{"id": "bad\nidentifier"}]}]},
    {"results": [{"vulns": [{"id": "x" * 129}]}]},
    {"results": [{"vulns": [{}]}]}, {"results": [{"vulns": [{}] * 101}]}])
def test_incomplete_or_invalid_advisories_never_pass_as_clean(payload):
    with pytest.raises(ValueError):
        parse_results(payload, PACKAGES)


def test_complete_empty_coverage_and_advisory_mapping():
    assert parse_results({"results": [{}]}, PACKAGES)[0]["advisory_ids"] == []
    rows = parse_results({"results": [{"vulns": [{"id": "GHSA-fixture"}]}]}, PACKAGES)
    assert rows == [{**PACKAGES[0], "advisory_ids": ["GHSA-fixture"]}]
