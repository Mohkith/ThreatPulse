import os
import json
from flask import Flask, render_template, request

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline.database import get_filtered_threats, get_summary

app = Flask(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))


@app.route("/")
def index():
    summary = get_summary()
    threats = get_filtered_threats()

    techstack_path = os.path.join(PROJECT_ROOT, "config", "techstack.json")
    techstack = None
    if os.path.exists(techstack_path):
        with open(techstack_path) as f:
            techstack = json.load(f)

    return render_template("dashboard.html",
        summary=summary,
        threats=threats,
        techstack=techstack
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
