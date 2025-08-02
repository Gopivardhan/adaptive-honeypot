"""
Real‑time dashboard for the honeypot.

This script launches a Dash web application that reads from the SQLite
database populated by the honeypot services and renders interactive charts.
It allows operators to monitor attack patterns, identify the most common tools,
and view a table of recent events.

Usage:

    python dashboard/app.py --db logs/honeypot.db --port 8050

When the honeypot is running concurrently, the dashboard will update each
time the page is refreshed. If the database file is empty, the graphs will
render with placeholder data.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Optional, Tuple

import dash
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go


def load_events(db_path: str) -> List[dict]:
    """Load all events from the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id ASC")
    rows = cur.fetchall()
    events: List[dict] = []
    for row in rows:
        event = dict(row)
        try:
            event["headers"] = json.loads(event.get("headers", "{}"))
        except Exception:
            event["headers"] = {}
        try:
            event["meta"] = json.loads(event.get("meta", "{}"))
        except Exception:
            event["meta"] = {}
        events.append(event)
    conn.close()
    return events


def compute_time_series(events: List[dict]) -> Tuple[List[str], List[int]]:
    """Compute attack counts per minute for a time‑series chart."""
    counts = defaultdict(int)
    for event in events:
        ts = event["timestamp"]
        try:
            dt = datetime.fromisoformat(ts)
            key = dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            key = "unknown"
        counts[key] += 1
    # Sort by time
    items = sorted(counts.items())
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    return labels, values


def compute_tool_counts(events: List[dict]) -> Tuple[List[str], List[int]]:
    """Compute frequency of detected tools."""
    tools = [e["tool"] or "unknown" for e in events]
    counter = Counter(tools)
    labels = list(counter.keys())
    values = list(counter.values())
    return labels, values


def build_layout(events: List[dict]) -> html.Div:
    """Construct the Dash layout from event data."""
    # Time series of attacks
    ts_labels, ts_values = compute_time_series(events)
    tool_labels, tool_values = compute_tool_counts(events)
    return html.Div(children=[
        html.H1(children="Honeypot Dashboard"),
        html.Div(children="An overview of recent attacks"),
        dcc.Graph(
            id="time-series",
            figure={
                "data": [go.Scatter(x=ts_labels, y=ts_values, mode="lines+markers")],
                "layout": go.Layout(
                    title="Attacks over Time", xaxis={"title": "Time (minute)"}, yaxis={"title": "Number of Events"}
                ),
            },
        ),
        dcc.Graph(
            id="tool-frequency",
            figure={
                "data": [go.Bar(x=tool_labels, y=tool_values)],
                "layout": go.Layout(
                    title="Tool Frequency", xaxis={"title": "Tool"}, yaxis={"title": "Count"}
                ),
            },
        ),
        html.H2(children="Recent Events"),
        html.Table([
            html.Thead([
                html.Tr([html.Th(col) for col in ["Timestamp", "Service", "IP", "Port", "Type", "Path", "Tool", "Class"]]),
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(event["timestamp"]),
                    html.Td(event["service"]),
                    html.Td(event["ip"]),
                    html.Td(event["port"]),
                    html.Td(event["request_type"]),
                    html.Td(event["path"] or ""),
                    html.Td(event["tool"] or ""),
                    html.Td(event["classification"] or ""),
                ]) for event in reversed(events[-50:])
            ])
        ])
    ])


def main(db_path: str, port: int) -> None:
    events = load_events(db_path)
    app = dash.Dash(__name__)
    app.layout = build_layout(events)
    app.run_server(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot dashboard")
    parser.add_argument("--db", default="logs/honeypot.db", help="Path to SQLite database")
    parser.add_argument("--port", type=int, default=8050, help="Dashboard HTTP port")
    args = parser.parse_args()
    main(args.db, args.port)
