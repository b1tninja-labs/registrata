"""RFC 2167 Appendix C, transcribed from the source text rather than from this project.

Every code and every error text below was read out of https://www.rfc-editor.org/rfc/rfc2167.txt
(retrieved 2026-11-05) with the document fetched in full. This test exists because the project's
own transcription had previously drifted in a way nothing could detect: `check_server` whitelisted a
code 201, and 201 appears nowhere in RFC 2167 -- the only way anyone could tell was to trust a
transcription that was itself the thing under test. Fetching the appendix and asserting against it
removes that circularity.
"""

import pytest

from registrata.errors import ERROR_TEXT, ErrorCode

#: Appendix C, "an ordered list of RWhois error codes", verbatim.
APPENDIX_C: dict[int, str] = {
    120: "Registration deferred",
    130: "Object not authoritative",
    230: "No objects found",
    300: "Not compatible with version",
    320: "Invalid attribute",
    321: "Invalid attribute syntax",
    322: "Required attribute missing",
    323: "Object reference not found",
    324: "Primary key not unique",
    325: "Failed to update outdated object",
    330: "Exceeded maximum objects limit",
    331: "Invalid limit",
    332: "Nothing to transfer",
    333: "Not master for authority area",
    336: "Object not found",
    338: "Invalid directive syntax",
    340: "Invalid authority area",
    341: "Invalid class",
    342: "Invalid host/port",
    350: "Invalid query syntax",
    351: "Query too complex",
    352: "Invalid security method",
    353: "Authentication failed",
    354: "Encryption failed",
    400: "Directive not available",
    401: "Not authorized for directive",
    402: "Unidentified error",
    420: "Registration not authorized",
    436: "Invalid display format",
    500: "Memory allocation problem",
    501: "Service not available",
    502: "Unrecoverable error",
    503: "Idle time exceeded",
}

#: "The following error codes, defined in [RFC 1714], have been made obsolete."
OBSOLETE: frozenset[int] = frozenset(
    {100, 200, 231, 334, 335, 337, 421, 431, 432, 433, 434, 460, 461, 530}
)

#: Appendix C's meaning of each digit position.
FIRST_DIGIT: dict[int, str] = {
    1: "Information only, no action required",
    2: "Information, action required",
    3: "Specific command error, retry that command or try another one",
    4: "Serious for current command, may correct with another command",
    5: "Fatal, must disconnect",
}


def test_the_enum_is_exactly_appendix_c() -> None:
    """Neither more nor less: a code we invented is a bug, a code we omit is a gap."""
    assert sorted(int(code) for code in ErrorCode) == sorted(APPENDIX_C)


@pytest.mark.parametrize("code", sorted(APPENDIX_C))
def test_every_error_text_matches_the_source_text(code: int) -> None:
    assert ERROR_TEXT[code] == APPENDIX_C[code]


def test_no_obsolete_rfc1714_code_is_accepted() -> None:
    """Servers still running pre-1997 code sets must read as unknown, not as valid."""
    assert not {int(c) for c in ErrorCode} & OBSOLETE


def test_code_201_does_not_exist() -> None:
    """The specific historical drift this file was written for."""
    assert 201 not in APPENDIX_C
    assert 201 not in {int(code) for code in ErrorCode}
    assert 201 not in ERROR_TEXT


def test_no_implementation_specific_codes_have_been_sneaked_in() -> None:
    """Appendix C allows implementation-specific codes, but only with a 6 in the second position."""
    extra = {int(code) for code in ErrorCode} - set(APPENDIX_C)
    for code in extra:
        assert str(code)[1] == "6", (
            f"{code} is not a legal implementation-specific code"
        )


def test_the_informational_bands_are_the_ones_the_client_relies_on() -> None:
    """Why lookup.py treats below-300 as an answer and only 400+ as endpoint failure.

    Section 230 "No objects found" sits in the 2XX band, which Appendix C defines as
    "Information, action required" -- information, not an error. The bands below 300 are the ones a
    working server uses to say something true; 3XX onward are errors.
    """
    informational = [code for code in APPENDIX_C if code // 100 in {1, 2}]
    assert informational == [120, 130, 230]
    assert FIRST_DIGIT[230 // 100] == "Information, action required"
    assert int(ErrorCode.NO_OBJECTS_FOUND) in informational
