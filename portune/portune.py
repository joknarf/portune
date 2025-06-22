#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re-port.py - A utility to check port accessibility and generate HTML reports.

This script performs port scanning across multiple hosts and generates detailed reports
in both console and HTML formats. It supports parallel scanning, DNS resolution,
ping checks, and email notifications.

Author: joknarf
License: MIT
"""

from __future__ import annotations

# Standard library imports
import os
import sys
import platform
import argparse
import socket
import threading
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from html import escape
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import List, Dict, Tuple, Any, Optional, Union

# Constants and global variables

# Use system ping command based on the OS
# as raw socket ICMP ping requires privileges
OS = platform.system().lower()
if OS == "windows":
    PING = "ping -n 1 -w {timeoutms} {ip}"
elif OS == "darwin":  # macOS
    PING = "ping -c 1 -t {timeout} {ip}"
elif OS == "sunos":  # SunOS
    PING = "ping {ip} {timeout}"
elif OS == "aix":  # IBM AIX
    PING = "ping -c 1 -w {timeout} {ip}"
elif OS.startswith("hp-ux"):  # HP-UX 11.11+
    PING = "ping -n 1 -m {timeout} {ip}"
else:
    PING = "ping -c 1 -W {timeout} {ip}"



ICON = "data:image/svg+xml,%3Csvg height='200px' width='200px' version='1.1' id='Layer_1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' viewBox='0 0 508 508' xml:space='preserve' fill='%23000000'%3E%3Cg id='SVGRepo_bgCarrier' stroke-width='0'%3E%3C/g%3E%3Cg id='SVGRepo_tracerCarrier' stroke-linecap='round' stroke-linejoin='round'%3E%3C/g%3E%3Cg id='SVGRepo_iconCarrier'%3E%3Ccircle style='fill:%23ffbb06;' cx='254' cy='254' r='254'%3E%3C/circle%3E%3Cg%3E%3Ccircle style='fill:%234c4c4c;' cx='399.6' cy='252' r='55.2'%3E%3C/circle%3E%3Ccircle style='fill:%234c4c4c;' cx='150' cy='356' r='55.2'%3E%3C/circle%3E%3Ccircle style='fill:%234c4c4c;' cx='178.4' cy='127.2' r='55.2'%3E%3C/circle%3E%3C/g%3E%3Cpath style='fill:%23000000;' d='M301.2,282.4l15.6,1.2l6.4-19.2l-13.2-8c0.4-5.6,0-11.2-1.2-16.4l12-10l-9.2-18l-15.2,3.6 c-3.6-4-7.6-8-12.4-10.8l1.2-15.6l-19.2-6.4l-8,13.2c-5.6-0.4-11.2,0-16.4,1.2l-10-12l-18,8.8l3.6,15.2c-4,3.6-8,7.6-10.8,12.4 l-15.6-1.2l-6.4,19.2l13.2,8.4c-0.4,5.6,0,11.2,1.2,16.4l-12,10l9.2,18l15.2-3.6c3.6,4,7.6,8,12.4,10.8l-1.6,15.2l19.2,6.4l8.4-13.2 c5.6,0.4,11.2,0,16.4-1.2l10,12l18-8.8l-3.6-15.2C294.4,291.2,298.4,287.2,301.2,282.4z M242.4,286c-18.8-6.4-28.8-26.4-22.8-45.2 c6.4-18.8,26.8-29.2,45.6-22.8c18.8,6.4,28.8,26.4,22.8,45.2C281.6,282,261.2,292.4,242.4,286z'%3E%3C/path%3E%3Cpath style='fill:%23324A5E;' d='M380.4,304c-20.4,50-69.6,85.2-126.8,85.2c-18.8,0-36.8-4-53.6-10.8c-2.4,5.6-5.6,10.4-9.6,14.8 c19.2,8.8,40.8,13.6,63.2,13.6c65.6,0,122-41.2,144.4-99.2C392,307.2,386,306,380.4,304z M132,157.2c-20.4,26-32.8,59.2-32.8,94.8 c0,22.4,4.8,43.6,13.6,62.8c4.4-4,9.2-7.2,14.8-9.6c-6.8-16.4-10.8-34.4-10.8-53.2c0-30.4,10-58.8,27.2-81.6 C139.2,166.8,135.2,162.4,132,157.2z M253.6,97.6c-9.2,0-18.4,0.8-27.6,2.4c2.8,5.2,5.2,10.8,6.4,16.8c6.8-1.2,14-1.6,21.2-1.6 c57.2,0,106.4,35.2,126.8,85.2c5.6-2,11.2-3.2,17.2-3.2C375.6,138.8,319.6,97.6,253.6,97.6z'%3E%3C/path%3E%3Cg%3E%3Ccircle style='fill:%23FF7058;' cx='399.6' cy='252' r='28.4'%3E%3C/circle%3E%3Ccircle style='fill:%23FF7058;' cx='150' cy='356' r='28.4'%3E%3C/circle%3E%3Ccircle style='fill:%23FF7058;' cx='178.4' cy='127.2' r='28.4'%3E%3C/circle%3E%3C/g%3E%3C/g%3E%3C/svg%3E"
XL='data:image/svg+xml,<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"><path d="M12.5535 16.5061C12.4114 16.6615 12.2106 16.75 12 16.75C11.7894 16.75 11.5886 16.6615 11.4465 16.5061L7.44648 12.1311C7.16698 11.8254 7.18822 11.351 7.49392 11.0715C7.79963 10.792 8.27402 10.8132 8.55352 11.1189L11.25 14.0682V3C11.25 2.58579 11.5858 2.25 12 2.25C12.4142 2.25 12.75 2.58579 12.75 3V14.0682L15.4465 11.1189C15.726 10.8132 16.2004 10.792 16.5061 11.0715C16.8118 11.351 16.833 11.8254 16.5535 12.1311L12.5535 16.5061Z" fill="%23eee"></path><path d="M3.75 15C3.75 14.5858 3.41422 14.25 3 14.25C2.58579 14.25 2.25 14.5858 2.25 15V15.0549C2.24998 16.4225 2.24996 17.5248 2.36652 18.3918C2.48754 19.2919 2.74643 20.0497 3.34835 20.6516C3.95027 21.2536 4.70814 21.5125 5.60825 21.6335C6.47522 21.75 7.57754 21.75 8.94513 21.75H15.0549C16.4225 21.75 17.5248 21.75 18.3918 21.6335C19.2919 21.5125 20.0497 21.2536 20.6517 20.6516C21.2536 20.0497 21.5125 19.2919 21.6335 18.3918C21.75 17.5248 21.75 16.4225 21.75 15.0549V15C21.75 14.5858 21.4142 14.25 21 14.25C20.5858 14.25 20.25 14.5858 20.25 15C20.25 16.4354 20.2484 17.4365 20.1469 18.1919C20.0482 18.9257 19.8678 19.3142 19.591 19.591C19.3142 19.8678 18.9257 20.0482 18.1919 20.1469C17.4365 20.2484 16.4354 20.25 15 20.25H9C7.56459 20.25 6.56347 20.2484 5.80812 20.1469C5.07435 20.0482 4.68577 19.8678 4.40901 19.591C4.13225 19.3142 3.9518 18.9257 3.85315 18.1919C3.75159 17.4365 3.75 16.4354 3.75 15Z" fill="%23eee"></path></g></svg>'
CSS="""
<style>
body {
    font-family: Arial, sans-serif;
    overflow: auto;
}
.hidden {
    display: none;
}
.icon {
    border-radius: 25px;
    background-color: #444;
    color: #eee;
    padding: 10px 20px 2px 6px;
    background-image: url("{ICON}");
    background-repeat: no-repeat no-repeat;
    background-position: 12px 9px;    
    background-size: 24px;
    height: 30px;
    display: inline-block;
    text-indent: 40px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.60);
}
div {
    scrollbar-width: thin;
}
.blue, .green, .red {
  color: white;
  border-radius: 15px;
  text-align: center;
  font-weight: 700;
  display: inline-block;
  padding: 2px 5px;
}
.green { background-color: #4CAF50; }
.red { background-color: #f44336; }
.blue { background-color: #2196F3; }
.status {
    width: 150px;
}
.ping {
    width: 100px;
}
.pct {
    width: 60px;
    text-align: right;
    padding-right: 8px;
}
.desc {
    text-overflow: ellipsis;
    max-width: 200px;
    white-space: nowrap;
    overflow: hidden;
}
.desc:hover {
    overflow: visible;
    white-space: normal;
}
.table-container { 
    height: 90%;
    overflow-y: auto;
    position: relative;
    border-radius: 10px;
    border: 1px solid #aaa;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.40);
    margin-bottom: 10px;
}
#result-container {
    max-height: 800px; /* calc(100vh - 250px); */
}
table {
    width: 100%;
    border-collapse: collapse;
}
div.table-container table tr:hover {
    background-color: #f1f1f1;
}
th, td {
    text-align: left;
    border-bottom: 1px solid #ddd;
    white-space: nowrap;
}

td {
    padding: 4px 7px;; /* 2px 7px; */
}
th {
    padding: 7px; 
    background-color: #444;
    color: #eee;
    position: sticky;
    top: 0;
    z-index: 1;
    vertical-align: top;
}
.th-content {
    display: flex;
    align-items: center;
    gap: 5px;
    white-space: nowrap;
    font-weight: 600;
}
.sort-btn {
    color: #aaa;
    font-size: 10px;
    user-select: none;
    display: inline-block;
    width: 7px;
    text-align: center;
    flex-shrink: 0;
}
.sort-btn[data-sort-order="asc"] {
    color: #5a5;
}
.sort-btn[data-sort-order="desc"] {
    color: #5a5;
}
.column-filter {
    display: block;
    width: 90%;
    max-width: 300px;
    margin: 5px 0px 0px 0px;
    padding: 2px 5px;
    text-indent: 5px;
    border: 1px solid #666;
    border-radius: 15px;
    font-size: 12px;
    background: #444;
    color: #eee
}
.column-filter:focus {
    outline: none;
    border-color: #666;
    background: #ddd;
    color: #222;
}
.column-filter:focus::placeholder {
    color: transparent;
}
.column-filter::placeholder {
    font-size: 12px;
    color: #888;
}
.copy-icon {
    cursor: pointer;
}
.system-font {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
.copied {
    color: green; 
    margin-left: 5px;
}
.title-icon {
    display: inline;
    height: 30px;
    background-image: url("/static/images/favicon.svg");
    background-size: 30px 30px;
    background-repeat: no-repeat;
    background-position-y: -1px;
    vertical-align: bottom;
    padding-left: 35px;
}
.copy_clip {
    padding-right: 20px;
    background-repeat: no-repeat;
    background-position: right top;
    background-size: 20px 12px;
    white-space: nowrap;
}
.copy_clip:hover {
    cursor: pointer;
    background-image: url("/static/images/copy.svg");
}
.copy_clip_ok, .copy_clip_ok:hover {
    background-image: url("/static/images/copy_ok.svg");
}

.row-count {
    display: inline-block;
    font-size: 11px;
    font-weight: normal;
    border: 1px solid #aaa;
    border-radius: 17px;
    /* min-width: 17px; */
    text-align: center;
    /* text-indent: 14px;*/
    padding: 0px 18px 0px 4px;
    margin-left: auto;
    cursor: pointer;
    background-image: url('{XL}');
    background-repeat: no-repeat;
    background-position: right 4px center;
    background-size: 12px 12px;
}

</style>
""".replace("{ICON}", ICON).replace("{XL}", XL)
JS="""
<script src=https://unpkg.com/exceljs@4.1.1/dist/exceljs.min.js></script>
<script>
function initTableFilters(table) {
    const headers = table.querySelectorAll('thead th');
    headers.forEach((header, index) => {
        if (table==commandsTable) { 
            const contentSpan = document.createElement('span');
            contentSpan.className = 'th-content';
            
            // Add sort button first
            const sortBtn = document.createElement('span');
            sortBtn.className = 'sort-btn';
            sortBtn.innerHTML = '▲' //'&#11014;'; // Unicode for sort icon ▼
            sortBtn.style.cursor = 'pointer';
            sortBtn.setAttribute('data-sort-order', '');
            sortBtn.onclick = () => toggleSort(table, index, sortBtn);

            const titleSpan = document.createElement('span');
            titleSpan.className = 'th-title';
            titleSpan.innerHTML = header.innerHTML;

            // Move existing elements into the content span
            //while (header.firstChild) {
            //    contentSpan.appendChild(header.firstChild);
            //}
            
            // Add sort button at the beginning
            contentSpan.appendChild(sortBtn);
            contentSpan.appendChild(titleSpan);

            //contentSpan.insertBefore(sortBtn, contentSpan.firstChild);
            
            // Add export button and row counter for last column
            if (index === headers.length - 1) {
                // Add row counter
                const rowCount = document.createElement('span');
                rowCount.className = 'row-count system-font';
                rowCount.title = 'Export to Excel';
                rowCount.onclick = () => exportToExcel(table);
                contentSpan.appendChild(rowCount);
            }
            
            header.innerHTML = '';
            header.appendChild(contentSpan);
            
            // Add filter input
            const input = document.createElement('input');
            input.type = 'search';
            input.className = `column-filter input-${index}`;
            input.placeholder = '\\uD83D\\uDD0E\\uFE0E';
            input.addEventListener('input', () => applyFilters(table));
            header.appendChild(input);
        }
    });
    // Initialize row count
    updateRowCount(table, table.querySelectorAll('tbody tr:not(.hidden)').length);
}

function updateRowCount(table, count) {
    const rowCount = table.querySelector('.row-count');
    const totalRows = table.querySelectorAll('tbody tr').length;
    if (rowCount) {
        rowCount.innerHTML = ` ${count}/${totalRows}`; // &#129095;🡇 not working macOS
    }
}

function toggleSort(table, colIndex, sortBtn) {
    // Reset other sort buttons
    table.querySelectorAll('.sort-btn').forEach(btn => {
        if (btn !== sortBtn) {
            btn.setAttribute('data-sort-order', '');
            btn.innerHTML = '▲'; //'&#11014;';
        }
    });

    // Toggle sort order
    const currentOrder = sortBtn.getAttribute('data-sort-order');
    let newOrder = 'asc';
    if (currentOrder === 'asc') {
        newOrder = 'desc';
        sortBtn.innerHTML = '▼'; //'&#11015;';
    } else if (currentOrder === 'desc') {
        newOrder = '';
        sortBtn.innerHTML = '▲'; //'&#11014;';
    } else {
        sortBtn.innerHTML = '▲'; //'&#11014;';
    }
    sortBtn.setAttribute('data-sort-order', newOrder);
    sortBtn.setAttribute('data-col-index', colIndex); // Store column index on the button
    applyFilters(table);
}

function applyFilters(table) {
    table.classList.add('hidden');
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    const filters = Array.from(table.querySelectorAll('.column-filter'))
        .map(filter => ({
            value: filter.value.toLowerCase(),
            index: filter.parentElement.cellIndex,
            regexp: filter.value ? (() => {
                try { return new RegExp(filter.value, 'i'); } 
                catch(e) { return null; }
            })() : null
        }));

    // First apply filters
    const filteredRows = rows.filter(row => {
        // If no filters are active, show all rows
        //if (filters.every(f => !f.value)) {
        //    row.classList.remove('hidden');
        //    return true;
        //}
        const cells = row.cells;
        const shouldShow = !filters.some(filter => {
            if (!filter.value) return false;
            const cellText = cells[filter.index]?.innerText || '';
            if (filter.regexp) return !filter.regexp.test(cellText);
            return !cellText.toLowerCase().includes(filter.value);
        });
        if (shouldShow) {
            row.classList.remove('hidden');
        } else {
            row.classList.add('hidden');
        }
        return shouldShow;
    });

    // Update row count
    updateRowCount(table, filteredRows.length);

    // Then apply sorting if active
    const sortBtn = table.querySelector('.sort-btn[data-sort-order]:not([data-sort-order=""])');
    if (sortBtn) {
        const colIndex = parseInt(sortBtn.getAttribute('data-col-index'));
        const sortOrder = sortBtn.getAttribute('data-sort-order');
        
        filteredRows.sort((a, b) => {
            const aVal = a.cells[colIndex]?.innerText.trim() || '';
            const bVal = b.cells[colIndex]?.innerText.trim() || '';
            
            // Check if both values are numeric
            const aNum = !isNaN(aVal) && !isNaN(parseFloat(aVal));
            const bNum = !isNaN(bVal) && !isNaN(parseFloat(bVal));
            
            if (aNum && bNum) {
                // Numeric comparison
                return sortOrder === 'asc' 
                    ? parseFloat(aVal) - parseFloat(bVal)
                    : parseFloat(bVal) - parseFloat(aVal);
            }
            
            // Fallback to string comparison
            if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
            if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
            return 0;
        });

        // Reorder visible rows
        const tbody = table.querySelector('tbody');
        filteredRows.forEach(row => tbody.appendChild(row));
    }
    table.classList.remove('hidden');
}

function processHtmlContent(element) {
    function processLi(li, level = 0) {
        const indent = '    '.repeat(level);
        const items = [];
        
        // Extraire le texte direct (avant sous-liste)
        const textContent = Array.from(li.childNodes)
            .filter(node => node.nodeType === Node.TEXT_NODE)
            .map(node => node.textContent.trim())
            .join(' ')
            .replace(/\\s+/g, ' ')
            .trim();
            
        if (textContent) {
            items.push(indent + '• ' + textContent);
        }
        
        // Traiter récursivement les sous-listes
        const subLists = li.querySelectorAll(':scope > ul > li');
        if (subLists.length) {
            for (const subLi of subLists) {
                items.push(...processLi(subLi, level + 1));
            }
        }
        
        return items;
    }

    const list = element.querySelector('ul');
    if (list) {
        const items = Array.from(list.children)
            .filter(el => el.tagName === 'LI')
            .map(li => processLi(li))
            .flat();
        return items.join('\\n');
    }
    const text = element.textContent.replace(/\\s+/g, ' ').trim();
    // Return object with type info if it's a number
    if (/^\\d+$/.test(text)) {
        return { value: parseInt(text, 10), type: 'integer' };
    }
    return text;
}

function exportToExcel(table, fileNamePrefix = 'export') {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Sheet1', {
        views: [{ state: 'frozen', xSplit: 0, ySplit: 1 }]
    });

    // Get headers and data
    const headers = Array.from(table.querySelectorAll('thead th'))
        .map(th => th.querySelector('.th-title')?.textContent.trim() || '');

    // Get data rows with type information
    const rows = Array.from(table.querySelectorAll('tbody tr'))
        .filter(row => ! row.classList.contains('hidden'))
        .map(row => 
            Array.from(row.cells)
                .map(cell => {
                    const content = processHtmlContent(cell);
                    if (content && typeof content === 'object' && content.type === 'integer') {
                        return content.value; // Numbers will be handled as numbers by ExcelJS
                    }
                    return (typeof content === 'string' ? content : content.toString())
                })
        );

    // Calculate optimal column widths based on content
    const columnWidths = headers.map((header, colIndex) => {
        // Start with header width
        let maxWidth = header.length;

        // Check width needed for each row's cell in this column
        rows.forEach(row => {
            const cellContent = row[colIndex];
            if (cellContent === null || cellContent === undefined) return;

            // Convert numbers to string for width calculation
            const contentStr = cellContent.toString();
            // Get the longest line in multiline content
            const lines = contentStr.split('\\n');
            const longestLine = Math.max(...lines.map(line => line.length));
            maxWidth = Math.max(maxWidth, longestLine);
        });

        // Add some padding and ensure minimum/maximum widths
        return { width: Math.min(Math.max(maxWidth + 5, 10), 100) };
    });

    // Define columns with calculated widths
    worksheet.columns = headers.map((header, index) => ({
        header: header,
        key: header,
        width: columnWidths[index].width
    }));

    // Add data rows
    rows.forEach(rowData => {
        const row = worksheet.addRow(rowData);
        row.alignment = { vertical: 'top', wrapText: true };
        
        // Set row height based on content, handling both strings and numbers
        // const maxLines = Math.max(...rowData.map(cell => {
        //     if (cell === null || cell === undefined) return 1;
        //     const str = cell.toString();
        //     return (str.match(/\\n/g) || []).length + 1;
        // }));
        // row.height = Math.max(20, maxLines * 15);
    });

    // Style header row
    const headerRow = worksheet.getRow(1);
    // headerRow.font = { bold: true };
    // headerRow.alignment = { vertical: 'middle', horizontal: 'left' };
    // headerRow.height = 20;

    // Add table after all rows are defined
    worksheet.addTable({
        name: 'DataTable',
        ref: 'A1',
        headerRow: true,
        totalsRow: false,
        style: {
            theme: 'TableStyleMedium2',
            showRowStripes: true,
        },
        columns: headers.map(h => ({
            name: h,
            filterButton: true
        })),
        rows: rows
    });

    // Save file
    workbook.xlsx.writeBuffer().then(buffer => {
        const blob = new Blob([buffer], { 
            type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' 
        });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileNamePrefix + '_' + new Date().toISOString().slice(0,10) + '.xlsx';
        a.click();
        window.URL.revokeObjectURL(url);
    });
}

let commandsTable = document.querySelector('#commandTable');
document.addEventListener('DOMContentLoaded', () => {
    if (commandsTable) initTableFilters(commandsTable);
    document.querySelector('.input-4').value = '{FILTER}';
});
</script>
"""
# Get system information
HOSTNAME = socket.gethostname()

def get_local_ip():
    try:
        # Get all IP addresses associated with the hostname
        ip_list = socket.gethostbyname_ex(HOSTNAME)[2]
        # Filter out the loopback address
        local_ips = [ip for ip in ip_list if not ip.startswith("127.")]
        return local_ips[0] if local_ips else ""
    except Exception:
        return ""

MY_IP = get_local_ip()

class ProgressBar:
    """A progress bar for displaying task completion status in the terminal.
    
    The progress bar shows completion percentage, task count, and processing speed
    in a dynamic, updating display.

    Attributes:
        total (int): Total number of tasks to be completed
        prefix (str): Text to display before the progress bar
        length (int): Length of the progress bar in characters
        current (int): Current number of completed tasks
        start_time (float): Time when the progress bar was initialized
    """

    def __init__(self, total: int, prefix: str = 'Progress:', length: int = 50) -> None:
        """Initialize the progress bar.

        Args:
            total: Total number of tasks to track
            prefix: Text to display before the progress bar
            length: Visual length of the progress bar in characters
        """
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0
        self.start_time = time.time()

    def update(self, increment: int = 1) -> None:
        """Update the progress bar by incrementing the completed task count.

        Updates the display to show current progress, percentage complete,
        and processing speed. Automatically handles terminal output formatting.

        Args:
            increment: Number of tasks completed in this update
        """
        self.current += increment
        filled_length = int(self.length * self.current / self.total)
        bar = '█' * filled_length + '-' * (self.length - filled_length)
        percentage = f"{100 * self.current / self.total:.1f}%"
        elapsed_time = time.time() - self.start_time
        speed = self.current / elapsed_time if elapsed_time > 0 else 0


        # Create the progress message
        progress_msg = f'{self.prefix} |{bar}| {percentage} ({self.current}/{self.total}) [{speed:.1f} ports/s]'
        # Add padding to ensure old content is cleared
        try:
            col = os.get_terminal_size(2).columns
        except OSError:
            col = 80
        padding = ' ' * (col - len(progress_msg) - 1)

        sys.stderr.write('\r' + progress_msg[:col - 1] + padding)
        sys.stderr.flush()
        if self.current == self.total:
            sys.stderr.write('\n')
            sys.stderr.flush()

def parse_input_file(filename: str, info_command: Optional[str] = None) -> List[Tuple[str, List[int]]]:
    """Parse the input file containing host and port information.

    Reads a text file where each line contains a hostname and optionally a list of ports.
    Lines starting with # are treated as comments and ignored.
    If a line contains only a hostname, port 22 is assumed.
    Port lists can be comma-separated.

    Args:
        filename: Path to the input file

    Returns:
        A list of tuples, each containing:
            - hostname (str): The target hostname or IP address
            - ports (List[int]): List of ports to scan for that host
            - desc (str): Optional description for the host

    Examples:
        Input file format:
            # Comment line
            host1 22,80,443
            host2
            host3 8080

        Will return:
            [
                ('host1', [22, 80, 443]),
                ('host2', [22]),
                ('host3', [8080])
            ]
    """
    host_dict = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            words = line.split()
            fqdn = words[0].lower()
            ports = words[1] if len(words) > 1 else '22'
            port_list = [int(p) for p in ports.split(',')]
            desc = ' '.join(words[2:]).strip().split('|') if len(words) > 2 else []
            if fqdn in host_dict:
                existing_ports, existing_desc = host_dict[fqdn]
                host_dict[fqdn] = (list(set(existing_ports + port_list)), existing_desc or desc)
            else:
                host_dict[fqdn] = (port_list, desc)
    desc_titles = []
    if info_command: 
        res = subprocess.run(info_command, shell=True, input='\n'.join(host_dict.keys())+'\n', text=True, capture_output=True)
        lines = res.stdout.splitlines()
        desc_titles = lines[0].strip().split('\t')[1:]  # Get the description titles from the first line
        lines.pop(0)  # Remove the first line with titles
        for line in lines:
            info = line.strip().split('\t')
            fqdn = info[0].lower()
            info.pop(0)  # Remove the hostname from the info list
            if fqdn in host_dict:
                host_dict[fqdn] = (host_dict[fqdn][0], info)
    hosts = []
    for fqdn in  host_dict:
        ports, desc = host_dict[fqdn]
        hosts.append((fqdn, sorted(ports), desc))
    return (hosts, desc_titles)

def ping_host(ip: str, timeout: int = 2) -> bool:
    """Test if a host responds to ICMP ping.

    Uses the system ping command to check host availability. The command is
    configured for a single ping attempt with a specified timeout.

    Args:
        ip: IP address to ping
        timeout: Maximum time to wait for response in seconds

    Returns:
        True if host responds to ping, False otherwise
    """
    timeoutms = str(int(timeout * 1000))
    ping_cmd = PING.format(ip=ip, timeout=timeout, timeoutms=timeoutms).split()
    try:
        output = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 1)
        return output.returncode == 0
    except Exception:
        return False

def is_ip(hostname: str) -> bool:
    """Check if a given hostname is an IP address.

    Uses inet_aton to determine if the input string is a valid
    IPv4 address.

    Args:
        hostname: The hostname or IP address to check

    Returns:
        True if the hostname is an IP address, False otherwise
    """
    try:
        socket.inet_aton(hostname)
        return True
    except socket.error:
        return False

def resolve_and_ping_host(hostname: str, timeout: int = 2, noping: bool = False) -> Tuple[str, Dict[str, Union[str, bool]]]:
    """Resolve a hostname to IP and optionally check if it responds to ping.

    Performs DNS resolution and ping check in a single function. For IP addresses,
    attempts reverse DNS lookup to get the hostname.

    Args:
        hostname: Hostname or IP address to resolve
        timeout: Timeout for DNS and ping operations in seconds
        noping: If True, skip the ping check

    Returns:
        A tuple containing:
            - str: The hostname (which might be updated from reverse DNS)
            - dict: Host information with keys:
                - 'ip': IP address or 'N/A' if resolution fails
                - 'ping': Boolean ping status
                - 'hostname': Original resolved hostname (only if different from input)
    """
    try:
        # If it's an IP, try to get hostname from reverse DNS
        if is_ip(hostname):
            try:
                ip = hostname
                resolved_hosts = socket.gethostbyaddr(ip)
                if resolved_hosts and resolved_hosts[0]:
                    hostname = resolved_hosts[0]  # Use the resolved hostname
            except (socket.herror, socket.gaierror):
                pass  # Keep the IP as hostname if reverse lookup fails
        else:
            ip = socket.gethostbyname(hostname)
        if noping:
            return hostname, {'ip': ip, 'ping': False}
        ping_status = ping_host(ip, timeout)
        return hostname, {'ip': ip, 'ping': ping_status}
    except Exception:
        return hostname, {'ip': 'N/A', 'ping': False}

def ping_hosts(hosts: List[Tuple[str, List[int], str]], 
             timeout: int = 2, 
             parallelism: int = 10, 
             noping: bool = False) -> Dict[str, Dict[str, Union[str, bool]]]:
    """Process DNS resolution and ping checks for multiple hosts in parallel.

    Uses a thread pool to concurrently resolve hostnames to IPs and optionally
    check their ping status. Includes a progress bar to show completion status.

    Args:
        hosts: List of (hostname, ports) tuples to process
        timeout: Maximum time to wait for each operation in seconds
        parallelism: Maximum number of concurrent threads to use
        noping: If True, skip the ping checks

    Returns:
        Dictionary mapping hostnames to their information:
            hostname -> {
                'ip': IP address or 'N/A' if resolution fails,
                'ping': Boolean ping status,
                'hostname': Original resolved hostname (if different from input)
            }
    """
    results = {}
    
    if noping:
        print("Resolving DNS...", file=sys.stderr)
    else:
        print("Resolving DNS and pinging hosts...", file=sys.stderr)
    progress_bar = ProgressBar(len(hosts), prefix='Host Discovery')
    
    # Use a lock for thread-safe progress updates
    lock = threading.Lock()
    
    def _update_progress(_):
        with lock:
            progress_bar.update(1)
    
    with ThreadPoolExecutor(max_workers=parallelism) as executor:
        future_to_host = {
            executor.submit(resolve_and_ping_host, hostname, timeout, noping): hostname
            for hostname, _, _ in hosts
        }
        
        # Add callback to update progress bar when each future completes
        for future in future_to_host:
            future.add_done_callback(_update_progress)
        
        for future in as_completed(future_to_host):
            orig_hostname = future_to_host[future]
            resolved_hostname, info = future.result()
            # Store with original hostname as key for matching with ports later
            results[orig_hostname] = info
            if resolved_hostname != orig_hostname:
                # Keep resolved hostname in the info dict
                results[orig_hostname]['hostname'] = resolved_hostname
    
    print(file=sys.stderr)  # New line after progress bar
    return results

def check_port(hostname: str, 
             port: int, 
             host_info: Dict[str, Union[str, bool]],
             desc: list,
             timeout: int = 2) -> Tuple[str, str, int, str, bool]:
    """Check if a specific TCP port is accessible on a host.

    Attempts to establish a TCP connection to the specified port. Uses pre-resolved
    IP address information to avoid redundant DNS lookups.

    Args:
        hostname: The hostname to check
        port: The TCP port number to check
        host_info: Dictionary containing pre-resolved host information:
            - 'ip': IP address or 'N/A' if resolution failed
            - 'ping': Boolean indicating ping status
            - 'hostname': Optional resolved hostname from reverse DNS
        desc: Optional description for the host
        timeout: Maximum time to wait for connection in seconds

    Returns:
        Tuple containing:
            - display_hostname: Either the original or resolved hostname
            - ip: The IP address or 'N/A' if resolution failed
            - port: The port number that was checked
            - status: Connection status (CONNECTED/TIMEOUT/REFUSED/UNREACHABLE)
            - ping: Boolean indicating if the host responded to ping
            - desc: Optional description for the host
        
    Status meanings:
        CONNECTED: Successfully established TCP connection
        TIMEOUT: Connection attempt timed out
        REFUSED: Host actively refused the connection
        UNREACHABLE: Network error or host unreachable
        RESOLVE_FAIL: Could not resolve hostname to IP
    """
    if host_info['ip'] == 'N/A':
        return (hostname, host_info['ip'], port, 'RESOLVE_FAIL', host_info['ping'], desc)
    
    # Use resolved hostname if available
    display_hostname = host_info.get('hostname', hostname)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host_info['ip'], port))
        s.close()
        return (display_hostname, host_info['ip'], port, 'CONNECTED', host_info['ping'], desc)
    except ConnectionAbortedError:
        return (display_hostname, host_info['ip'], port, 'CONNECTED', host_info['ping'], desc)
    except (TimeoutError, socket.timeout):
        return (display_hostname, host_info['ip'], port, 'TIMEOUT', host_info['ping'], desc)
    except ConnectionRefusedError:
        return (display_hostname, host_info['ip'], port, 'REFUSED', host_info['ping'], desc)
    except Exception:
        # Handle other network errors (filtered, network unreachable, etc)
        return (display_hostname, host_info['ip'], port, 'UNREACHABLE', host_info['ping'], desc)

def send_email_report(
    output_file: str,
    mailhost: str,
    sender: str,
    recipients: List[str],
    subject: str,
    stats: Dict[str, Any],
    parallelism: int,
    timeout: float
) -> bool:
    """Send the HTML report as an email attachment with a summary in the body.

    Creates a multipart email with:
    1. An HTML body containing a summary of the scan results
    2. The full HTML report as an attachment

    Args:
        output_file: Path to the generated HTML report file
        mailhost: SMTP server hostname
        sender: Email address of the sender
        recipients: List of recipient email addresses
        subject: Email subject line
        stats: Dictionary containing scan statistics and results
        parallelism: Number of parallel threads used in scan
        timeout: Timeout value used in scan

    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = subject
    style = '''
<style>
html { font-size: 10%; color: #fff; }
h3 { color: #444; margin: 10px 0 5px; }
table { border-collapse: collapse; margin-right: 20px; }
th, td { font-size: 85%; padding: 2px 4px; text-align: left; border-bottom: 1px solid #ddd; }
th { background-color: #444; color: #eee; }
.green { color: green; }
.red { color: red; }
</style>
'''
    # Create HTML body with scan summary
    html_body = f'''
<html>
<head>
<meta charset="utf-8">
{style}
</head>
<body>
<h3>Port Scan Summary from {HOSTNAME} ({MY_IP})</h3>'''
    
    html_body += generate_html_summary(stats, parallelism, timeout)
    html_body += '''
<p>Please find the full detailed report attached.</p>
</body>
</html>
'''

    # Add HTML body and attachment
    msg.attach(MIMEText(html_body, 'html'))
    with open(output_file, 'rb') as f:
        attachment = MIMEApplication(f.read(), _subtype='html')
        attachment.add_header('Content-Disposition', 'attachment', filename=output_file)
        msg.attach(attachment)

    # Send email using SMTP
    try:
        with smtplib.SMTP(mailhost) as server:
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}", file=sys.stderr)
        return False

def format_percent(value: int, total: int) -> Tuple[str, str]:
    """Format a value as a percentage with separate value/total and percent strings.

    Args:
        value: The count to calculate percentage for
        total: The total count to calculate percentage against

    Returns:
        A tuple containing:
            - str: Formatted as "value/total"
            - str: Formatted as "xx.x%" with one decimal place
    """
    if total == 0:
        return "0/0", "0.0%"
    return f"{value}/{total}", f"{(value/total*100):.1f}%"

def get_vlan_base(ip: str, bits: int) -> str:
    """Calculate VLAN base address with end padding 0."""
    if ip == 'N/A':
        return 'N/A'
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return 'invalid'

        # Convert IP to 32-bit integer
        ip_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(octets))

        # Apply mask
        mask = ((1 << bits) - 1) << (32 - bits)
        masked_ip = ip_int & mask

        # Convert back to dotted notation
        result_octets = [(masked_ip >> (24 - 8 * i)) & 255 for i in range(4)]
        return '.'.join(map(str, result_octets))
    except:
        return 'N/A'


def compute_stats(
    results: List[Tuple[str, str, int, str, bool]],
    start_time: float,
    bits: int) -> Dict[str, Any]:
    """Compute comprehensive statistics from scan results.

    Processes the raw scan results to generate statistics about:
    - Overall scan duration and counts
    - Host status (pingable, unreachable, etc.)
    - Port status (connected, refused, etc.)
    - Domain-specific statistics
    - VLAN timeout patterns

    Args:
        results: List of scan results, each containing:
            - hostname
            - ip
            - port
            - status (CONNECTED/TIMEOUT/REFUSED/etc.)
            - ping status
        start_time: Timestamp when the scan started

    Returns:
        Dictionary containing various statistics categories:
        - duration: Total scan time
        - total_ports: Number of ports scanned
        - ports: Counts by port status
        - total_hosts: Number of unique hosts
        - hosts: Counts by host status
        - domains: Statistics by domain
        - vlan_timeouts: Timeout patterns by VLAN
        - Various formatted summaries for display
    """
    stats = {
        'duration': time.time() - start_time,
        'total_ports': len(results),
        'ports': {
            'connected': sum(1 for r in results if r[3] == 'CONNECTED'),
            'refused': sum(1 for r in results if r[3] == 'REFUSED'),
            'timeout': sum(1 for r in results if r[3] == 'TIMEOUT'),
            'unreachable': sum(1 for r in results if r[3] == 'UNREACHABLE'),
            'resolve_fail': sum(1 for r in results if r[3] == 'RESOLVE_FAIL')
        },
        'vlan_timeouts': defaultdict(lambda: {'timeouts': 0, 'total': 0}),
        'vlan_bits': bits,
    }



    # Collect VLAN statistics for timeouts
    for hostname, ip, port, status, _, _ in results:
        if ip != 'N/A':
            try:
                vlan = get_vlan_base(ip, bits)
                stats['vlan_timeouts'][vlan]['total'] += 1
                if status == 'TIMEOUT':
                    stats['vlan_timeouts'][vlan]['timeouts'] += 1
            except:
                pass


    # Group results by hostname for host statistics
    host_stats = defaultdict(lambda: {'statuses': [], 'ping': False})
    for result in results:
        hostname, _, _, status, ping, _ = result
        host_stats[hostname]['statuses'].append(status)
        host_stats[hostname]['ping'] |= ping

    stats.update({
        'total_hosts': len(host_stats),
        'hosts': {
            'pingable': sum(1 for host in host_stats.values() if host['ping']),
            'all_open': sum(1 for host in host_stats.values() if all(s in ['CONNECTED', 'REFUSED'] for s in host['statuses'])),
            'with_timeout': sum(1 for host in host_stats.values() if any(s == 'TIMEOUT' for s in host['statuses'])),
            'unresolved': sum(1 for host in host_stats.values() if all(s == 'RESOLVE_FAIL' for s in host['statuses']))
        }
    })
    
    # Compute domain statistics
    domain_stats = defaultdict(lambda: {
        'hosts': set(),
        'ports': defaultdict(lambda: {
            'connected': 0,
            'refused': 0,
            'timeout': 0,
            'unreachable': 0,
            'resolve_fail': 0,
            'total': 0
        })
    })
    
    for hostname, ip, port, status, _, _ in results:
        if is_ip(hostname):
            # For IP addresses, use VLAN/16 as domain
            domain = '.'.join(hostname.split('.')[:2]) + '.0.0'
        else:
            # Not an IP address, extract domain normally
            parts = hostname.split('.')
            if len(parts) > 1:
                domain = '.'.join(parts[1:])  # Remove first part to get domain
            else:
                domain = 'local'  # For hostnames without domain

        domain_stats[domain]['hosts'].add(hostname)
        domain_stats[domain]['ports'][port]['total'] += 1
        domain_stats[domain]['ports'][port][status.lower()] += 1
    
    # Create formatted domain statistics with port grouping
    stats['domains'] = {}
    for domain, dstats in domain_stats.items():
        # Separate ports into two groups: <=1024 and >1024
        low_ports = {p: stats for p, stats in dstats['ports'].items() if p <= 1024}
        high_ports = {p: stats for p, stats in dstats['ports'].items() if p > 1024}
        # Calculate combined stats for high ports
        if high_ports:
            high_ports_combined = {
                'connected': sum(s['connected'] for s in high_ports.values()),
                'refused': sum(s['refused'] for s in high_ports.values()),
                'timeout': sum(s['timeout'] for s in high_ports.values()),
                'unreachable': sum(s['unreachable'] for s in high_ports.values()),
                'resolve_fail': sum(s['resolve_fail'] for s in high_ports.values()),
                'total': sum(s['total'] for s in high_ports.values())
            }
        else:
            high_ports_combined = None
            
        stats['domains'][domain] = {
            'total_hosts': len(dstats['hosts']),
            'low_ports': low_ports,
            'high_ports': high_ports_combined
        }

    # Create formatted summary data for display
    def format_percent(value, total):
        if total == 0:
            return "0/0 (0.0%)"
        return f"{value}/{total} ({(value/total*100):.1f}%)"
    
    # Host status items
    stats['hosts_summary'] = [
        ("Responding to ping", lambda s: format_percent(s['hosts']['pingable'], s['total_hosts'])),
        ("All ports open", lambda s: format_percent(s['hosts']['all_open'], s['total_hosts'])),
        ("Not responding to ping", lambda s: format_percent(s['total_hosts'] - s['hosts']['pingable'], s['total_hosts'])),
        ("Failed to resolve", lambda s: format_percent(s['hosts']['unresolved'], s['total_hosts'])),
        ("With timeout ports", lambda s: format_percent(s['hosts']['with_timeout'], s['total_hosts']))
    ]
    
    # Port status items
    stats['ports_summary'] = [
        ("Connected", lambda s: {'value': s['ports']['connected'], 'total': s['total_ports']}),
        ("Refused", lambda s: {'value': s['ports']['refused'], 'total': s['total_ports']}),
        ("Timeout", lambda s: {'value': s['ports']['timeout'], 'total': s['total_ports']}),
        ("Unreachable", lambda s: {'value': s['ports']['unreachable'], 'total': s['total_ports']}),
        ("Failed to resolve", lambda s: {'value': s['ports']['resolve_fail'], 'total': s['total_ports']})
    ]
    
    # Domain status items
    stats['domains_summary'] = []
    for domain, dstats in sorted(stats['domains'].items()):
        total_hosts = dstats['total_hosts']
        stats['domains_summary'].append((
            domain,
            lambda s, d=domain: {
                'total_hosts': s['domains'][d]['total_hosts'],
                'ports': (
                    # Add low ports (<=1024)
                    [(
                        port,
                        {
                            'connected': pstats['connected'],
                            'refused': pstats['refused'],
                            'timeout': pstats['timeout'],
                            'total': pstats['total']
                        }
                    ) for port, pstats in sorted(s['domains'][d]['low_ports'].items())]
                    +
                    # Add high ports (>1024) as a single combined entry if they exist
                    ([
                        ('>1024',
                         {
                             'connected': s['domains'][d]['high_ports']['connected'],
                             'refused': s['domains'][d]['high_ports']['refused'],
                             'timeout': s['domains'][d]['high_ports']['timeout'],
                             'total': s['domains'][d]['high_ports']['total']
                         }
                    )] if s['domains'][d]['high_ports'] else [])
                )
            }
        ))
    
    # Add Scan Summary items
    stats['scan_summary'] = [
        ("Date (duration)", lambda s: f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))} ({s['duration']:.2f}s)"),
        ("Total hosts scanned", lambda s: str(s['total_hosts'])),
        ("Total ports scanned", lambda s: str(s['total_ports']))
    ]

    return stats

def generate_html_report(
    results: List[Tuple[str, str, int, str, bool]],
    output_file: str,
    scan_time: time.struct_time,
    timeout: float,
    parallelism: int,
    noping: bool,
    stats: Dict[str, Any],
    input_file: str = '',
    desc_titles: List[str] = [],
    filter: str = '',
) -> None:
    """Generate a complete HTML report of the port scan results.

    Creates a detailed HTML report including:
    - A table of all scan results
    - Summary statistics
    - Domain and VLAN analysis
    - Interactive features for sorting and filtering

    The report uses custom CSS for styling and JavaScript for interactivity.

    Args:
        results: List of scan results, each containing:
            - hostname (str)
            - ip (str)
            - port (int)
            - status (str)
            - ping status (bool)
        output_file: Path where the HTML report should be saved
        scan_time: Time when the scan was started
        timeout: Timeout value used for port checks
        parallelism: Number of parallel threads used
        noping: Whether ping checks were disabled
        stats: Dictionary containing all computed statistics
        input_file: Path to the input file used for the scan (for report header)
    """

    with open(output_file, 'w', encoding='utf-8') as f:
        # Write HTML header with CSS and metadata
        f.write(f'''<!DOCTYPE html>
<html>
<head>
    <title>re-port: {HOSTNAME}</title>
    <meta charset="utf-8">
    <link rel="icon" href="{ICON}" type="image/svg+xml">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    {CSS}
</head>
<body>''')

        # Write report header
        f.write(f'<h3 class="icon">Port Accessibility Report from {HOSTNAME} ({MY_IP}) to {os.path.basename(input_file)} - {time.strftime("%Y-%m-%d %H:%M:%S", scan_time)}</h3>\n')
        
        # Write detailed results table
        if not desc_titles:
            _, _, _, _, _, desc = results[0]
            desc_titles = ["Description" for d in desc]
        f.write(f'''
        <div class="table-container" id="result-container">
            <table id="commandTable">
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>IP</th>
                        <th>VLAN/{stats['vlan_bits']}</th>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Ping</th>
                        {"""
                         """.join([f"<th>{d}</th>" for d in desc_titles])}
                    </tr>
                </thead>
                <tbody>
        ''')

        # Add result rows
        for hostname, ip, port, status, ping, desc in results:
            ping_status = 'UP' if ping else 'N/A' if noping else 'DOWN'
            ping_class = 'green' if ping else 'blue' if noping else 'red'
            status_class = 'green' if status == 'CONNECTED' else 'blue' if status == 'REFUSED' else 'red'
            row_class = ''
            if filter and status != filter:
                row_class = 'hidden'
            f.write(f'''
                <tr class="{row_class}">
                    <td>{escape(str(hostname))}</td>
                    <td>{escape(str(ip))}</td>
                    <td>{str(get_vlan_base(ip, stats['vlan_bits']))}</td>
                    <td style="text-align: right;">{port}</td>
                    <td style="text-align: center;"><span class="{status_class} status">{escape(status)}</span></td>
                    <td style="text-align: center;"><span class="{ping_class} ping">{ping_status}</span></td>
                    {"""
                    """.join([f'<td class="desc">{escape(desc[i] if i < len(desc) else "")}</td>' for i in range(len(desc_titles))])}
                </tr>
            ''')

        f.write('</tbody></table></div>\n')

        # Add summary and statistics
        f.write(generate_html_summary(stats, parallelism, timeout))
        
        # Add JavaScript for interactivity
        f.write(f'</body>{JS.replace("{FILTER}", filter)}</html>\n')

def print_statistics(stats, timeout, parallelism):
    def format_percent(value, total):
        if total == 0:
            return "0/0", "0.0%"
        return f"{value}/{total}", f"{(value/total*100):.1f}%"

    # Print Scan Summary
    print("\nScan Summary:", file=sys.stderr)
    for label, value_func in stats['scan_summary']:
        print(f"  {label}: {value_func(stats)}", file=sys.stderr)
    print(f"  Parallel threads: {parallelism}", file=sys.stderr)
    print(f"  Timeout: {timeout:.1f} seconds", file=sys.stderr)

    # Print Hosts Status
    print("\nHosts Status:", file=sys.stderr)
    for label, value_func in stats['hosts_summary']:
        print(f"  {label}: {value_func(stats)}", file=sys.stderr)

    # Print Ports Status
    print("\nPorts Status:", file=sys.stderr)
    for label, value_func in stats['ports_summary']:
        data = value_func(stats)
        value_str, pct_str = format_percent(data['value'], data['total'])
        print(f"  {label}: {value_str} ({pct_str})", file=sys.stderr)

    # Print DNS Domain Statistics
    print("\nDNS Domain Statistics:", file=sys.stderr)
    
    # Define columns and their headers
    headers = ['Domain', 'Total Hosts', 'Port', 'Connected/Refused', '%', 'Timeout', '%']
    
    # Get maximum width for each column based on content
    widths = {
        'Domain': max(len('Domain'), max((len(str(d)) for d, _ in stats['domains_summary']))),
        'Total Hosts': len('Total Hosts'),
        'Port': len('Port'),
        'Connected/Refused': len('Connected/Refused'),
        '%': len('100.0%'),
        'Timeout': len('Timeout'),
        '%_2': len('100.0%')
    }

    # Update widths based on actual data
    for domain, value_func in stats['domains_summary']:
        domain_data = value_func(stats)
        widths['Total Hosts'] = max(widths['Total Hosts'], len(str(domain_data['total_hosts'])))
        for port, port_stats in domain_data['ports']:
            widths['Port'] = max(widths['Port'], len(str(port)))
            connected_refused = port_stats['connected'] + port_stats['refused']
            cr_value, cr_pct = format_percent(connected_refused, port_stats['total'])
            timeout_value, timeout_pct = format_percent(port_stats['timeout'], port_stats['total'])
            widths['Connected/Refused'] = max(widths['Connected/Refused'], len(cr_value))
            widths['Timeout'] = max(widths['Timeout'], len(timeout_value))

    # Create the format string for each row
    row_format = '| {:<{}} | {:>{}} | {:>{}} | {:>{}} | {:>{}}'
    row_format += ' | {:>{}} | {:>{}} |'
    
    # Create separator line
    separator = '+' + '+'.join('-' * (w + 2) for w in widths.values()) + '+'

    # Print header
    print(separator, file=sys.stderr)
    print(row_format.format(
        'Domain', widths['Domain'],
        'Total Hosts', widths['Total Hosts'],
        'Port', widths['Port'],
        'Connected/Refused', widths['Connected/Refused'],
        '%', widths['%'],
        'Timeout', widths['Timeout'],
        '%', widths['%_2']
    ), file=sys.stderr)
    print(separator, file=sys.stderr)

    # Print data rows
    for domain, value_func in stats['domains_summary']:
        domain_data = value_func(stats)
        first_row = True
        for port, port_stats in domain_data['ports']:
            connected_refused = port_stats['connected'] + port_stats['refused']
            cr_value, cr_pct = format_percent(connected_refused, port_stats['total'])
            timeout_value, timeout_pct = format_percent(port_stats['timeout'], port_stats['total'])
            
            print(row_format.format(
                domain if first_row else '', widths['Domain'],
                str(domain_data['total_hosts']) if first_row else '', widths['Total Hosts'],
                str(port), widths['Port'],
                cr_value, widths['Connected/Refused'],
                cr_pct, widths['%'],
                timeout_value, widths['Timeout'],
                timeout_pct, widths['%_2']
            ), file=sys.stderr)
            first_row = False
        if not first_row:  # Only print separator between domains if domain had data
            print(separator, file=sys.stderr)

def format_table_output(
    results: List[Tuple[str, str, int, str, bool]], 
    noping: bool
) -> str:
    """Format scan results as a text table for terminal output.

    Creates a formatted ASCII table with columns aligned and proper borders.
    Adapts the output format based on whether stdout is a terminal or not.

    Args:
        results: List of scan results, each containing:
            - hostname (str)
            - ip (str)
            - port (int)
            - status (str)
            - ping status (bool)
        noping: Whether ping checks were disabled

    Returns:
        str: Formatted table string ready for terminal output
    """
    # Define columns and their headers
    headers = ['Hostname', 'IP', 'Port', 'Status', 'Ping']
    
    # Get maximum width for each column based on content
    widths = {
        'Hostname': max(len('Hostname'), max((len(str(r[0])) for r in results))),
        'IP': max(len('IP'), max((len(str(r[1])) for r in results))),
        'Port': max(len('Port'), max((len(str(r[2])) for r in results))),
        'Status': max(len('Status'), max((len(str(r[3])) for r in results))),
        'Ping': max(len('Ping'), max((len('UP' if r[4] else 'DOWN') for r in results)))
    }

    # Create the format string for each row based on terminal type
    if sys.stdout.isatty():
        row_format = '| {:<{}} | {:<{}} | {:>{}} | {:<{}} | {:<{}} |'
        separator = '+' + '+'.join('-' * (w + 2) for w in widths.values()) + '+'
    else:
        row_format = '{:<{}} {:<{}} {:>{}} {:<{}} {:<{}}'
        separator = '-' * (sum(widths.values()) + len(headers) * 3 + 1)

    # Create the table string
    table = []
    table.append(separator)
    
    # Add header
    table.append(row_format.format(
        'Hostname', widths['Hostname'],
        'IP', widths['IP'],
        'Port', widths['Port'],
        'Status', widths['Status'],
        'Ping', widths['Ping']
    ))
    table.append(separator)
    
    # Add data rows
    for hostname, ip, port, status, ping, desc in results:
        ping_status = 'UP' if ping else 'N/A' if noping else 'DOWN'
        table.append(row_format.format(
            str(hostname), widths['Hostname'],
            str(ip), widths['IP'],
            str(port), widths['Port'],
            str(status), widths['Status'],
            ping_status, widths['Ping']
        ))
    
    table.append(separator)
    return '\n'.join(table)

def main():
    parser = argparse.ArgumentParser(description='Port accessibility report utility')
    parser.add_argument('-p', '--parallelism', type=int, default=50, help='Number of parallel threads (default: 50)')
    parser.add_argument('-t', '--timeout', type=float, default=2, help='Timeout in seconds for port and ping checks (default: 2)')
    parser.add_argument('-o', '--output', default=f'report_{HOSTNAME}.{time.strftime("%Y%m%d_%H%M%S")}.html', help='Output HTML report file')
    parser.add_argument('-n', '--noping', action="store_true", help='No ping check')
    parser.add_argument('-s', '--summary', action="store_true", help='Print scan summary information')
    parser.add_argument('-b', '--bits', type=int, default=16, help='VLAN bits for timeout summary (default: 16)')
    parser.add_argument('-d', '--desc_titles', type=str, nargs='*', help='List of custom description titles for hosts (optional)')
    parser.add_argument('-f', '--filter', type=str, help='default status filter for html report (optional)',
                        choices=['CONNECTED', 'REFUSED', 'TIMEOUT', 'UNREACHABLE', 'RESOLVE_FAIL'], default='')
    parser.add_argument('-i', '--info_command', type=str, help='Exernal command to get hosts information (optional)',)

    # Email related arguments
    email_group = parser.add_argument_group('Email Options')
    email_group.add_argument('--email-to', help='Comma-separated list of email recipients')
    email_group.add_argument('--email-from', help='Sender email address')
    email_group.add_argument('--email-subject', help='Email subject')
    email_group.add_argument('--mailhost', default='mailhost', help='Mail server host (default: mailhost)')

    parser.add_argument('input_file', help='Input file with hostnames and ports (fqdn port1,port2,...)')

    args = parser.parse_args()

    start_time = time.time()
    scan_datetime = time.localtime()
    if not os.path.exists(args.input_file):
        print(f"Input file '{args.input_file}' does not exist.", file=sys.stderr)
        sys.exit(1)
    (hosts, desc_titles) = parse_input_file(args.input_file, args.info_command)
    if not hosts:
        print(f"No valid hosts found in input file '{args.input_file}'.", file=sys.stderr)
        sys.exit(1)
    # First, do DNS resolution and ping in one pass
    host_info = ping_hosts(hosts, args.timeout, args.parallelism, args.noping)
    
    # Calculate total tasks and initialize progress bar
    total_tasks = sum(len(ports) for _, ports, _ in hosts)
    print(f"Preparing to scan {len(hosts)} hosts with {total_tasks} total ports...", file=sys.stderr)
    
    # Prepare tasks with pre-resolved data
    tasks = []
    for hostname, ports, desc in hosts:
        for port in ports:
            tasks.append((hostname, port, host_info[hostname], desc))

    results = []
    lock = threading.Lock()
    
    # Create progress bar
    progress_bar = ProgressBar(total_tasks, prefix='Scanning')
    
    with ThreadPoolExecutor(max_workers=args.parallelism) as executor:
        future_to_task = {executor.submit(check_port, hostname, port, info, desc, args.timeout): (hostname, port, info) 
                         for hostname, port, info, desc in tasks}
        
        for future in as_completed(future_to_task):
            res = future.result()
            with lock:
                results.append(res)
                progress_bar.update(1)
    
    # Add a newline after progress bar completion
    print(file=sys.stderr)

    # Calculate all statistics in one place
    stats = compute_stats(results, start_time, args.bits)
    
    # Generate report
    results.sort(key=lambda x: (x[0], x[2]))
    generate_html_report(
        results,
        args.output,
        time.localtime(start_time),
        args.timeout,
        args.parallelism,
        args.noping,
        stats,
        args.input_file,
        args.desc_titles or desc_titles or [],
        args.filter,
    )
    
    # Print summary
    # Display detailed results in table format
    print(format_table_output(results, args.noping))
    if args.summary:
        print_statistics(stats, args.timeout, args.parallelism)

    print(f"\nReport generated: {args.output}", file=sys.stderr)

    # Send email if recipient is provided
    if args.email_to:
        recipients = [r.strip() for r in args.email_to.split(',')]
        if send_email_report(
            args.output,
            args.mailhost,
            args.email_from or f'port-scanner@{HOSTNAME}',
            recipients,
            args.email_subject or f'Port Scan Report {HOSTNAME} ({MY_IP}) to {os.path.basename(args.input_file)}',
            stats,
            args.parallelism,
            args.timeout
        ):
            print(f"Report sent via email to: {', '.join(recipients)}", file=sys.stderr)
        else:
            print("Failed to send email report", file=sys.stderr)
def format_percent(value, total):
    """Format a value as a percentage with the format: value/total with percent in separate output"""
    if total == 0:
        return "0/0", "0.0%"
    return f"{value}/{total}", f"{(value/total*100):.1f}%"

def generate_html_summary(
    stats: Dict[str, Any], 
    parallelism: int, 
    timeout: float
) -> str:
    """Generate HTML summary tables from scan statistics.

    Creates HTML tables showing:
    1. Scan summary (timing, counts)
    2. Host status statistics
    3. Port status statistics
    4. Domain and VLAN statistics

    Args:
        stats: Dictionary containing all scan statistics
        parallelism: Number of parallel threads used
        timeout: Timeout value used in seconds

    Returns:
        str: HTML string containing formatted tables
    """
    html = []
    
    # Summary table layout
    html.append('<table><tr style="vertical-align: top;">')

    # Scan Summary section
    html.append('''
    <td style="border: 0;">
    <div class="table-container">
    <table><tr><th>Scan Summary</th><th>Value</th></tr>''')
    
    for label, value_func in stats['scan_summary']:
        html.append(f'<tr><td>{label}</td><td>{value_func(stats)}</td></tr>')
    html.append(f'<tr><td>Parallel threads</td><td>{parallelism}</td></tr>')
    html.append(f'<tr><td>Timeout</td><td>{timeout:.1f}s</td></tr>')
    html.append('</table></div></td>')

    # Hosts Status section
    html.append('''
    <td style="border: 0;">
    <div class="table-container">
    <table><tr><th>Hosts Status</th><th style="text-align: right;">Value</th><th style="text-align: right;">%</th></tr>''')
    
    for label, value_func in stats['hosts_summary']:
        value_str = value_func(stats)
        if ' (' in value_str:
            value, pct = value_str.split(' (')
            pct = pct.rstrip(')')
            html.append(f'''<tr>
                <td>{label}</td>
                <td style="text-align: right;">{value}</td>
                <td style="text-align: right;">{pct}</td>
            </tr>''')
    html.append('</table></div></td>')

    # Ports Status section
    html.append('''
    <td style="border: 0;">
    <div class="table-container">
    <table><tr><th>Ports Status</th><th style="text-align: right;">Value</th><th style="text-align: right;">%</th></tr>''')
    
    for label, value_func in stats['ports_summary']:
        data = value_func(stats)
        value_str, pct_str = format_percent(data['value'], data['total'])
        html.append(f'''<tr>
            <td>{label}</td>
            <td style="text-align: right;">{value_str}</td>
            <td style="text-align: right;">{pct_str}</td>
        </tr>''')
    html.append('</table></div></td>')
    html.append('</tr></table>')
    
    # DNS Domain Statistics
    html.append(f'''
    <table><tr style="vertical-align: top;">
    <td style="border: 0;"><h3>Summary for Domains/Ports</h3>
    <div class="table-container" style="display: inline-block;">
    <table><thead><tr>
        <th>Domain</th>
        <th style="text-align: right;">Total Hosts</th>
        <th style="text-align: right;">Port</th>
        <th style="text-align: right;">Connected/Refused</th>
        <th style="text-align: right;">%</th>
        <th style="text-align: right;">Timeout</th>
        <th style="text-align: right;">%</th>
    </tr></thead><tbody>''')

    # Add domain statistics
    for domain, value_func in stats['domains_summary']:
        domain_data = value_func(stats)
        first_row = True
        for port, port_stats in domain_data['ports']:
            connected_refused = port_stats['connected'] + port_stats['refused']
            cr_value, cr_pct = format_percent(connected_refused, port_stats['total'])
            timeout_value, timeout_pct = format_percent(port_stats['timeout'], port_stats['total'])
            tm_class = 'green' if port_stats['timeout'] == 0 else 'red' if port_stats['timeout'] == port_stats['total'] else 'blue'
            
            html.append(f'''<tr>
                <td>{'<strong>' + domain + '</strong>' if first_row else ''}</td>
                <td style="text-align: right;">{domain_data['total_hosts'] if first_row else ''}</td>
                <td style="text-align: right;">{port}</td>
                <td style="text-align: right;">{cr_value}</td>
                <td style="text-align: right;">{cr_pct}</td>
                <td style="text-align: right;">{timeout_value}</td>
                <td style="text-align: center;"><span class="{tm_class} pct">{timeout_pct}</span></td>
            </tr>''')
            first_row = False

    html.append('</tbody></table></div>')
    html.append('</td><td style="border: 0;">')

    # VLAN Timeout Statistics
    if stats['vlan_timeouts']:
        html.append(f'''
        <h3>VLAN/{stats['vlan_bits']} with Timeout</h3>
        <div class="table-container" style="display: inline-block;">
        <table><tr><th>VLAN/{stats['vlan_bits']}</th><th style="text-align: right;">Timeouts</th>
        <th style="text-align: right;">Total</th><th style="text-align: right;">%</th></tr>''')
        
        # Sort VLANs by timeout percentage (descending)
        sorted_vlans = sorted(
            stats['vlan_timeouts'].items(),
            key=lambda x: (x[1]['timeouts'] / x[1]['total'] if x[1]['total'] > 0 else 0),
            reverse=True
        )
        
        for vlan, data in sorted_vlans:
            if data['timeouts']:
                value_str, pct_str = format_percent(data['timeouts'], data['total'])
                tm_class = 'red' if data['timeouts'] == data['total'] else 'green' if data['timeouts'] == 0 else 'blue'
                html.append(f'''<tr>
                    <td>{vlan}</td>
                    <td style="text-align: right;">{data['timeouts']}</td>
                    <td style="text-align: right;">{data['total']}</td>
                    <td style="text-align: center;"><span class="{tm_class} pct">{pct_str}</span></td>
                </tr>''')
        html.append('</table></div>')
    
    html.append('</td></tr></table>')
    return '\n'.join(html)

if __name__ == '__main__':
    main()
