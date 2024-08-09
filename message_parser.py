"""
Utility module to parse log message.
"""

import re


def parse_message(message: str) -> dict:
    """
    Function to parse log message and 
    provides desired properties-value as output.
    
    Parameters:
    message (str): Input message to parse.

    Returns:
    dict: Parsed message in key-value pair.
    """

    # Initializing values to default to normalize the output for downstream.
    cat = cs1label = cs1 = cs2label = cs2 = cs3label = cs3 = ""
    cs4label = cs4 = cn1label = cn1 = msg = dhost = dst = ""

    # Creating a default message for exception handling.
    formatted_message = {
        "cat": cat,
        "cs1Label": cs1label,
        "cs1": cs1,
        "cs2Label": cs2label,
        "cs2": cs2,
        "cs3Label": cs3label,
        "cs3": cs3,
        "cs4Label": cs4label,
        "cs4": cs4,
        "cn1Label": cn1label,
        "cn1": cn1,
        "msg": msg,
        "dhost": dhost,
        "dst": dst,
    }

    try:
        # Regular expression to match key-value pattern
        pattern = re.compile(r'(\w+)=([^=\s].*?)(?=\s\w+=|\s*$)')

        # Find all matches from input message
        matches = pattern.findall(message)

        # Let's convert matches to a dictionary
        matched_msg = dict(map(lambda msg_val: (msg_val[0].strip(),
                                                msg_val[1].strip()),
                               matches))

        # Merging default formatted message to form matching messages
        formatted_message = {**formatted_message, **matched_msg}

    except Exception as ex:
        print(f"Failed to parse the message with error: \n {ex}")

    return formatted_message
