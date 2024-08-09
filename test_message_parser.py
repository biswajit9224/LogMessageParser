"""
Testing module for log message parser.
"""

from message_parser import parse_message


def test_parse_message_valid_message():
    """
    Test parse_message with valid message
    Returns:
    """
    input_message = """
        SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING 
cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags 
cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 
cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1
        """
    expected_output = {
        'cat': 'C2',
        'cs1Label': 'subcat',
        'cs1': 'DNS_TUNNELING',
        'cs2Label': 'vueUrls',
        'cs2': 'https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650',
        'cs3Label': 'Tags',
        'cs3': 'USA,Finance',
        'cs4Label': 'Url',
        'cs4': 'https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323',
        'cn1Label': 'severityScore',
        'cn1': '900',
        'msg': 'Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS.',
        'dhost': 'bad.com',
        'dst': '1.1.1.1'
    }

    assert parse_message(input_message) == expected_output


def test_parse_message_missing_value():
    """
    Test parse_message with valid message
    Returns:
    """
    input_message = """
        SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 
cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 
cn1Label=severityScore cn1=900 dhost=bad.com dst=1.1.1.1
        """

    expected_output = {
        'cat': 'C2',
        'cs1Label': '', 'cs1': '',
        'cs2Label': '', 'cs2': '',
        'cs3Label': '', 'cs3': 'USA,Finance',
        'cs4Label': 'Url', 'cs4': 'https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323',
        'cn1Label': 'severityScore', 'cn1': '900',
        'msg': '',
        'dhost': 'bad.com',
        'dst': '1.1.1.1'
    }

    assert parse_message(input_message) == expected_output


def test_parse_message_empty_message():
    """
    Test parse_message with valid message
    Returns:
    """
    input_message = ""

    expected_output = {
        'cat': '',
        'cs1Label': '', 'cs1': '',
        'cs2Label': '', 'cs2': '',
        'cs3Label': '', 'cs3': '',
        'cs4Label': '', 'cs4': '',
        'cn1Label': '', 'cn1': '',
        'msg': '',
        'dhost': '',
        'dst': ''
    }

    assert parse_message(input_message) == expected_output


if __name__ == "__main__":
    test_parse_message_valid_message()
    test_parse_message_missing_value()
    test_parse_message_empty_message()
