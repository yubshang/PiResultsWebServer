from flask import Flask
import os
import json
import ConfigParser
import time
import cache

module_directory = os.path.dirname(os.path.abspath(__file__))

# This makes sure that it always uses the same relative file paths
os.chdir(module_directory)  # Change working directory to the module instead of where it's executed from

# Read configuration file
config = ConfigParser.ConfigParser()
config.readfp(open(os.path.join(module_directory, "config.txt")))

cache_directory = config.get("Options", "cache_directory")
result_directory = config.get("Options", "result_directory")  # Results directory is configurable
should_cache = config.getboolean("Options", "cache_html")  # True if should cache
cache_limit = config.getint("Options", "cache_limit")  # Will start deleting caches after the limit has been reached

if not os.path.isdir(cache_directory):
    os.mkdir(cache_directory)
# Ensure the path to the static folder is correct
app = Flask(__name__, static_folder=os.path.join(module_directory, "static"))


def yes_no_to_boolean_str(yn):
    return str(yn == "Y")


def bool_str_to_color(bool_str, inverse=False):
    """
    Converts boolean to respective color. Can be inverted if inverse is True
    """
    if inverse is True:
        if bool_str == "True":
            return "danger"
        else:
            return "success"
    else:
        if bool_str == "True":
            return "success"
        else:
            return "danger"


def http_to_color(code):
    """
    Returns the color used in the table for specific http codes
    """
    if str.startswith(code, "2"):  # Success
        return "success"
    elif str.startswith(code, "3"):  # Redirect
        return 'warning'
    elif str.startswith(code, "4"):  # Failure
        return 'danger'
    else:
        return ''


@app.route("/results/<result>")
def display_analysis_table(result):
    """
    Generates and displays the html for the analysis table
    """

    absolute_file_path = os.path.join(result_directory, result)

    # Check Cache for HTML
    if should_cache is True:
        cached_html = cache.get_html_from_cache(absolute_file_path, cache_directory)
        if cached_html is not None:
            return cached_html  # If found, just output the cached html
    with open(absolute_file_path) as data_file:
        data = json.load(data_file)
        if data is None:
            return "Invalid JSON File"
        html_string = ""
        html_string += """<!DOCTYPE html>
<html>
<head>
<style>
/*
table, th, td {
    border: 1px solid black;
    border-collapse: collapse;
}
*/

table.sortable thead {
    background-color:#eee;
    color:#666666;
    font-weight: bold;
    cursor: default;
}

/*
th, td {
    padding: 5px;
}
*/

.table th, .table td{
    text-align: center;
}
</style>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap-theme.min.css">
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
<script src="/static/sortable.js"></script>
</head>
<body>

<div class="row">
<div class="col-md-6">
<table class="sortable table table-bordered">
  <tr>
    <th class="col-sm-2">Result id</th>
    <th class="col-sm-2">Sequence Number Anomaly</th>
    <th class="col-sm-2">UDP Traceroute Succeed</th>
    <th class="col-sm-2">HTTP GET Status</th>
    <th class="col-sm-2">DNS Tampering</th>
    <th class="col-sm-2">Block Page</th>
  </tr>"""
        blank_result = '<td> </td>'
        for result in data:
            html_string += "\n<tr>"
            html_string += '<td>' + result["result id"] + '</td>'
            if "sequence number anomaly" in result:
                seq_anom = yes_no_to_boolean_str(result["sequence number anomaly"])
                html_string += '<td class= ' + bool_str_to_color(seq_anom, True) + '>' + seq_anom + '</td>'
            else:
                html_string += blank_result
            if "UDP traceroute succeed" in result:
                udp_success = yes_no_to_boolean_str(result["UDP traceroute succeed"])
                html_string += '<td class= ' + bool_str_to_color(udp_success) + '>' + udp_success + '</td>'
            else:
                html_string += blank_result
            if "HTTP GET status" in result:
                http_code = result["HTTP GET status"]
                html_string += '<td class= ' + http_to_color(str(http_code)) + '>' + str(http_code) + '</td>'
            else:
                html_string += blank_result
            dns_tampering = yes_no_to_boolean_str(result["DNS tampering"])
            html_string += '<td class= ' + bool_str_to_color(dns_tampering, True) + '>' + dns_tampering + '</td>'
            if "block page" in result:
                blockpage = yes_no_to_boolean_str(result["block page"])
                html_string += '<td class= ' + bool_str_to_color(blockpage, True) + '>' + blockpage + '</td>'
            else:
                html_string += blank_result
            html_string += '</tr>'
        html_string += """</table>
</div>
</div>
</body>
</html>"""
        if should_cache:
            cache.cache_html(absolute_file_path, cache_directory, html_string)  # Cache HTML
            cache.check_cache(cache_directory, cache_limit)  # Check cache limit
    return html_string


@app.route("/")
def display_select_result_html():
    """
    Displays the html to select the results file that you want to view. This is the main page
    """
    html_string = ""
    html_string += """<HTML>
   <HEAD>
      <TITLE>
         Python Server
      </TITLE>
      <link rel="stylesheet" type="text/css" href="static/file_list.css" />
   </HEAD>
<BODY>
   <div style="text-align:center">
   <font size="6">Available Results</font>
   <br><br>
   <table align="center">
  <tr>
    <th>Result File</th>
    <th>Size</th>
    <th>Date Modified</th>
    <th>Date Created</th>
  </tr>
   """
    for result_file in os.listdir(result_directory):
        absolute_result_file_path = os.path.join(result_directory, result_file)
        html_string += "<tr>"
        html_string += "<td><div><a href=results/" + result_file + ">" + result_file + "</a></div></td>"
        html_string += "<td>" + str(os.path.getsize(absolute_result_file_path) / float(1000)) + "kb </td>"
        html_string += "<td>" + time.ctime(os.path.getmtime(absolute_result_file_path)) + "</td>"
        html_string += "<td>" + time.ctime(os.path.getctime(absolute_result_file_path)) + "</td>"
        html_string += "</tr>\n"
    html_string += """
    </table>
    </div>
    </BODY>
    </HTML>"""
    return html_string

if __name__ == "__main__":
    app.run(host="0.0.0.0")
