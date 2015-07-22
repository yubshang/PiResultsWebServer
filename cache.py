import hashlib
import base64
import os

"""
This cache system stores the html generated from the analysis tables. This is efficient because
generating the large html files can take a while, especially on lower end software like raspberry pis.

The cache system is based off the result's file MD5 so that if a new result file overwrites an old one with the same
name, new html will still be generated instead of showing the old one. Also, if a result file is renamed, it will
still return the cached HTML since MD5 is content based

The system stores the HTML in a file named as the Base32 Encoded MD5 hash of the result file it is generated from.
This allows the html to be retrieved from just reading the result file and generating the hash. The reason that
base32 encoding is used instead of base64 is that base64 isn't filename safe while base32 is.
"""


# Memory efficient method to MD5 hash large files
def hashfileMD5(file_path, blocksize=65536):
    with open(file_path, "rb") as afile:
        hasher = hashlib.md5()
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        afile.close()
    return hasher.digest()


def is_in_cache(result_file_path, cache_directory):
    base64_hash = base64.b32encode(hashfileMD5(result_file_path))
    cache_file_name = base64_hash + ".cache"
    return cache_file_name in os.listdir(cache_directory)


def get_html_from_cache(file_path, cache_directory):
    base64_hash = base64.b32encode(hashfileMD5(file_path))  # Use 32 bit encoding to ensure a valid filename
    cache_file_name = base64_hash + ".cache"
    is_in_cache = cache_file_name in os.listdir(cache_directory)
    if is_in_cache:
        with open(os.path.join(cache_directory, base64_hash + ".cache"), "r") as cached_file:
            html = cached_file.read()
            return html
    else:
        return None


def cache_html(result_file_path, cache_directory, html_string):
    base64_hash = base64.b32encode(hashfileMD5(result_file_path))  # Use 32 bit encoding to ensure a valid filename
    cached_file_path = os.path.join(cache_directory, base64_hash + ".cache")
    with open(cached_file_path, "w") as f:
        f.write(html_string)


def check_cache(cache_directory, cache_limit):
    """
    Checks cache to see if the caches exceed the cache limit. If it does, delete the oldest ones until the limit is
    met
    """
    files = []
    for file_name in os.listdir(cache_directory):
        absolute_file_path = os.path.join(cache_directory, file_name)
        if str.endswith(file_name, ".cache"):
            files.append(absolute_file_path)
    if len(files) > cache_limit:
        sorted_files = sorted(files, key=os.path.getmtime)
        while len(sorted_files) > cache_limit:
            oldest_file = sorted_files[0]
            os.remove(oldest_file)
            del sorted_files[0]
