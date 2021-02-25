#!/usr/bin/env python3

import gizmos.search
import gizmos.tree
import logging
import os
import requests
import subprocess

from flask import abort, Flask, render_template, request, Response

app = Flask(__name__)

browsers = {
    # "chebi": "Chemical Entities of Biological Interest",
    "go": "Gene Ontology",
    "ncbitaxon": "NCBI Organismal Classification",
    "obi": "Ontology for Biomedical Investigations",
    "pato": "Phenotype And Trait Ontology",
    "so": "Sequence Ontology",
    "uo": "Units of Measurement Ontology",
    "uberon": "Uberon Multi-Species Anatomy Ontology"
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/browser")
def browser():
    html = "<h3>Select a set of terms to browse:</h3>"
    html += "  <ul>"
    for ns, title in browsers.items():
        html += f'\n    <li><a href="/browser/{ns}">{title}</a></li>'
    html += "  </ul>"
    return render_template("base.html", default=html)


@app.route("/browser/<ns>")
def browse_ontology(ns):
    return get_tree(ns, None)


@app.route("/browser/<ns>/<term_id>")
def browse_ontology_at(ns, term_id):
    return get_tree(ns, term_id)


def get_database(resource):
    db_name = resource.lower()
    db = f"build/{db_name}.db"
    if not os.path.exists("build"):
        os.mkdir("build")
    if not os.path.exists(db):
        logging.info("Building database for " + resource)
        rc = subprocess.call(f"make build/{db_name}.db", shell=True)
        if rc != 0:
            return abort(500, description="Unable to create database for " + resource)
    return db


def get_tree(ns, term_id):
    db = get_database(ns)
    fmt = request.args.get("format", "")
    if fmt == "json":
        label = request.args.get("text", "")
        return gizmos.search.search(db, label, limit=30)

    href = "./{curie}"
    if not term_id:
        href = ns + "/{curie}"
    if ns not in browsers:
        return abort(500, description="Unknown ontology: " + ns)

    content = gizmos.tree.tree(
        db, term_id, title=browsers[ns], href=href, include_search=True
    )
    return render_template("base.html", default=content)
