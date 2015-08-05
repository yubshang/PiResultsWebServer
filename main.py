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


def bool_str_to_color(bool_str, inverse=False):
    """
    Converts boolean to respective color. Can be inverted if inverse is True
    """
    if inverse is True:
        if bool_str == "True":
            return "danger"
        elif bool_str == "False":
            return "success"
        else:
            return "default"
    else:
        if bool_str == "True":
            return "success"
        elif bool_str == "False":
            return "danger"
        else:
            return "default"


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
        return 'default'


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

.note_danger {
    position: relative;
}
.note_danger:after {
    content: "";
    position: absolute;
    top: 0;
    right: 0;
    width: 0;
    height: 0;
    display: block;
    border-left: 15px solid transparent;
    border-bottom: 15px solid transparent;
    border-top: 15px solid #f00;
}
.note_success {
    position: relative;
}
.note_success:after {
    content: "";
    position: absolute;
    top: 0;
    right: 0;
    width: 0;
    height: 0;
    display: block;
    border-left: 15px solid transparent;
    border-bottom: 15px solid transparent;
    border-top: 15px solid #006400;
}
.note_default {
    position: relative;
}
.note_default:after {
    content: "";
    position: absolute;
    top: 0;
    right: 0;
    width: 0;
    height: 0;
    display: block;
    border-left: 15px solid transparent;
    border-bottom: 15px solid transparent;
    border-top: 15px solid #c0c0c0;
}
</style>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap-theme.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.4/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
<script src="/static/sortable.js"></script>
<script>
$(function () {
    $("[data-toggle='popover']").popover();
});
</script>
</head>
<body>

<div class="row">
<div class="col-md-9">
<table class="sortable table table-bordered">
  <tr>
    <th class="col-sm-2">Url</th>
    <th class="col-sm-2">HTTP GET Status</th>
    <th class="col-sm-2">Block Page</th>
    <th class="col-sm-2">DNS Tampering</th>
    <th class="col-sm-2">Sequence Number Anomaly</th>
    <th class="col-sm-2">TTL Anomaly</th>
<!--    <th class="col-sm-2">UDP Traceroute Succeed</th> -->
  </tr>"""
        blank_result = '<td> </td>'
        for result in data:
            html_string += "\n<tr>"
            url_comment = ""
            if "url comment" in result:
                url_comment = result["url comment"]
            html_string += '<td title=' + '"' + url_comment + '"' + '>' + result["url"] + '</td>'
            if "status" in result:
                http_code = result["status"]
                http_comment = ""
                if "status comment" in result:
                    http_comment = result["status comment"]
                html_string += '<td class=' + http_to_color(str(http_code)) + ' title=' + '"' + http_comment + '"' + '>' + str(http_code) + '</td>'
            else:
                html_string += blank_result
            if "block page" in result:
                blockpage = str(result["block page"])
                blockpage_comment = ""
                if "extra" in result and "block page comment" in result["extra"]:
                    blockpage_comment = result["extra"]["block page comment"]
                if blockpage_comment:
                    style = bool_str_to_color(blockpage, True)
                    style += (" note_" + style)
                    title = "DNS tampering on <em>" + result['url'] + "</em>:"
                    html_string += ("<td class=\"" +  style + "\" " + "title=\"" + title + "\" " +
                                    "data-container=\"body\" data-toggle=\"popover\" " +
                                    "data-placement=\"bottom\" data-html=\"true\" " +
                                    "data-content=\"" + blockpage_comment +"\">" + blockpage  + "</td>")
                else:
                    html_string += '<td class=' + bool_str_to_color(blockpage, True) + ' title=' + '"' + blockpage_comment + '"' + '>' + blockpage + '</td>'
            else:
                html_string += blank_result
            if "dns tampering" in result:
                dns_tampering = str(result["dns tampering"])
                dns_comment = ""
                if "extra" in result and "dns tampering comment" in result["extra"]:
                    dns_comment = "<span>%s</span>" % result["extra"]["dns tampering comment"]
                if dns_comment:
                    style = bool_str_to_color(dns_tampering, True)
                    style += (" note_" + style)
                    title = "DNS tampering on <em>" + result['url'] + "</em>:"
                    html_string += ("<td class=\"" + style + "\" " + "title=\"" +  title +"\" " +
                                    "data-container=\"body\" data-toggle=\"popover\" " +
                                    "data-placement=\"bottom\" data-html=\"true\" " +
                                    "data-content=\"" + dns_comment +"\">" + dns_tampering + "</td>")
                else:
                    html_string += '<td class=' + bool_str_to_color(dns_tampering, True) + ' title=' + '"' + dns_comment + '"' + '>' + dns_tampering + '</td>'
            if "sequence number anomaly" in result:
                seq_anom = str(result["sequence number anomaly"])
                seq_comment = ""
                if "extra" in result and "sequence number anomaly comment" in result["extra"]:
                    seq_comment = result["extra"]["sequence number anomaly comment"]
                if seq_comment:
                    style = bool_str_to_color(seq_anom, True)
                    style += (" note_" + style)
                    title = "sequence number anomaly on <em>" + result['url'] + "</em>:"
                    html_string += ("<td class=\"" + style + "\" " + "title=\"" + title + "\" " +
                                    "data-container=\"body\" data-toggle=\"popover\" " +
                                    "data-placement=\"bottom\" data-html=\"true\" " +
                                    "data-content=\"" + seq_comment +"\">" + seq_anom + "</td>")
                else:
                    html_string += '<td class=' + bool_str_to_color(seq_anom, True) + ' title=' + '"' + seq_comment + '"' + '>' + seq_anom + '</td>'
            else:
                html_string += blank_result
            if "ttl anomaly" in result:
                ttl_anom = str(result["ttl anomaly"])
                ttl_extra = None
                if 'extra' in result:
                    ttl_extra = result['extra']
                ttl_comment = get_ttl_anomaly_comment(ttl_extra)
                if ttl_comment:
                    style = bool_str_to_color(ttl_anom, True)
                    style += (" note_" + style)
                    title = "TTL anomaly on <em>" + result['url'] + "</em>:"
                    html_string += ("<td class=\"" + style + "\" " + "title=\"" + title + "\" " +
                                    "data-container=\"body\" data-toggle=\"popover\" " +
                                    "data-placement=\"bottom\" data-html=\"true\" " +
                                    "data-content=\"" + ttl_comment +"\">" + ttl_anom + "</td>")
                else:
                    html_string += '<td class=' + bool_str_to_color(ttl_anom, True) + '>' + ttl_anom + '</td>'
            else:
                html_string += blank_result
#            if "UDP traceroute succeed" in result:
#                udp_success = str(result["UDP traceroute succeed"])
#                udp_comment = ""
#                if "UDP traceroute succeed comment" in result:
#                    udp_comment = result["UDP traceroute succeed comment"]
#                html_string += '<td class=' + bool_str_to_color(udp_success) + ' title=' + '"' + udp_comment + '"' + '>' + udp_success + '</td>'
#            else:
#                html_string += blank_result
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


def get_ttl_anomaly_comment(extra):
    ttl_comment = ""
    if extra is not None and type(extra) == dict:
        if "TTL anomalies" in extra:
            if "SYN-ACK IPID" in extra:
                ttl_comment += ("<span>SYN-ACK IPID: %d</span><br/>" %
                                extra['SYN-ACK IPID'])
                ttl_comment += ("<span>SYN-ACK TTL: %d</span><br/>" %
                                extra['SYN-ACK TTL'])
            else:
                ttl_comment = ("<span>SYN-ACK IPID: not found</span><br/>" +
                               "<span>SYN-ACK TTL: not found</span><br/>")
            ttl_comment += tabulate_ttl_anomalies(extra["TTL anomalies"])
    return ttl_comment


def tabulate_ttl_anomalies(ttl_anomalies):
    anomaly_table = ""
    if (ttl_anomalies is not None and type(ttl_anomalies) == list and
            len(ttl_anomalies) > 0):
        anomaly_table += "<br/><span>Anomalies: </span><br/>"
        anomaly_table += "<table class='table table-bordered'>"
        anomaly_table += "  <tr>"
        anomaly_table += "    <th class='col-sm-2'>No.</th>"
        anomaly_table += "    <th class='col-sm-2'>IPID</th>"
        anomaly_table += "    <th class='col-sm-2'>TTL</th>"
        anomaly_table += "    <th class='col-sm-6'>RST packet?</th>"
        anomaly_table += "  </tr>"
        counter = 1
        for anomaly_record in ttl_anomalies:
            anomaly_table += "  <tr>"
            anomaly_table += "    <td>%d</td>" % counter
            anomaly_table += "    <td>%d</td>" % anomaly_record['IPID']
            anomaly_table += "    <td>%d</td>" % anomaly_record['TTL']
            rst_flag = str(anomaly_record['RST injection'])
            style = bool_str_to_color(rst_flag, True)
            anomaly_table += "    <td class='%s'>%s</td>" % (style, rst_flag)
            anomaly_table += "  </tr>"
            counter = counter + 1
        anomaly_table += "</table>"
    return anomaly_table

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
    <th>Cached</th>
  </tr>
   """
    for result_file in os.listdir(result_directory):
        absolute_result_file_path = os.path.join(result_directory, result_file)
        html_string += "<tr>"
        html_string += "<td><div><a href=results/" + result_file + ">" + result_file + "</a></div></td>"
        html_string += "<td>" + str(os.path.getsize(absolute_result_file_path) / float(1000)) + "kb </td>"
        html_string += "<td>" + time.ctime(os.path.getmtime(absolute_result_file_path)) + "</td>"
        html_string += "<td>" + time.ctime(os.path.getctime(absolute_result_file_path)) + "</td>"
        cached = cache.is_in_cache(absolute_result_file_path, cache_directory)
        if cached:
            html_string += '<td><img src="static/checkmark.png" style="width:15px;height:15px;">'
        else:
            html_string += '<td><img src="static/x.png" style="width:15px;height:15px;">'
        html_string += "</tr>\n"
    html_string += """
    </table>
    </div>
    </BODY>
    </HTML>"""
    return html_string

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
