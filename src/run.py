#!/usr/bin/env python3

import csv
import gizmos.export
import gizmos.search
import gizmos.tree
import logging
import os
import requests
import sqlite3
import subprocess

from collections import defaultdict
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
    "uberon": "Uberon Multi-Species Anatomy Ontology",
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/browser")
def browser():
    html = "<h3>Select a set of terms to browse:</h3>\n"
    html += "  <ul>\n"
    for ns, title in browsers.items():
        html += f'\n    <li><a href="/browser/{ns}/">{title}</a></li>\n'
    html += "  </ul>\n"
    return render_template("base.html", default=html)


@app.route("/browser/<ns>/")
def browse_ontology(ns):
    return get_tree(ns, None)


@app.route("/browser/<ns>/<term_id>", methods=["GET", "POST"])
def browse_ontology_at(ns, term_id):
    message = ""
    if request.method == "POST":
        # Add the term to a list
        list_name = request.form["listName"]
        related_entities = request.form.getlist("relatedEntities")
        with open(f"build/lists/{list_name}.tsv", "a") as f:
            f.write("\t".join([term_id, ",".join(related_entities), ns]) + "\n")
        message += '<div class="alert alert-success alert-dismissible fade show" role="alert">\n'
        message += f'<h5 class="alert-heading">{term_id} added to list "{list_name}"</h5>\n'
        message += '<p class="mb-0">When finished, return to <a href="/export">Export</a> to export or delete your list.</p>\n'
        message += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>\n'
        message += "</div>\n"
    return get_tree(ns, term_id, message=message)


@app.route("/export")
def export():
    html = "<h3>Select an action:</h3>\n"
    html += "  <ul>\n"
    html += '    <li><a href="/export/new">Create a new list</a></li>\n'
    html += '    <li><a href="/export/lists">Export a list</a></li>\n'
    html += "  </ul>\n"

    html += "<h5>Actions TODO</h5>\n"
    html += "  <ul>\n"
    html += '    <li><a href="/export/edit">Edit a list</a></li>\n'
    html += '    <li><a href="/export/delete">Delete a list</a></li>\n'
    html += "  </ul>\n"

    return render_template("base.html", default=html)


@app.route("/export/new", methods=["GET", "POST"])
def new_list():
    message = ""
    if request.method == "POST":
        list_name = request.form["listName"]
        if not os.path.exists("build"):
            os.mkdir("build")
        if not os.path.exists("build/lists"):
            os.mkdir("build/lists")
        if os.path.exists(f"build/lists/{list_name}.tsv"):
            message += '<div class="alert alert-danger alert-dismissible" role="alert">'
            message += f'A list with the name "{list_name}" already exists. Please try again.'
            message += "</div>\n"
        else:
            f = open(f"build/lists/{list_name}.tsv", "x")
            f.close()
            message += '<div class="alert alert-success alert-dismissible" role="alert">\n'
            message += f'<h5 class="alert-heading">New list created with name "{list_name}"</h3>\n'
            message += '<p class="mb-0">You can now go to the <a href="/browser">Browser</a> to add terms to this list. '
            message += 'When finished, return to <a href="/export">Export</a> to export or delete your list.</p>\n'
            message += "</div>\n"
    return render_template("new_list.html", message=message)


@app.route("/export/lists", methods=["GET", "POST"])
def export_list():
    message = ""
    if request.method == "POST":
        list_name = request.form["listName"]
        properties = request.form.getlist("selectedProperties")
        output_format = request.form["formatOption"]
        return export(list_name, properties, output_format)
    lists = get_lists()
    return render_template("export_list.html", lists=lists, message=message)


def export(list_name, properties, output_format):
    if not os.path.exists(f"build/lists/{list_name}.tsv"):
        abort(400, description=f"File does not exist: build/lists/{list_name}.tsv")
    sources = defaultdict(set)
    terms = {}
    with open(f"build/lists/{list_name}.tsv", "r") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            term_id = row[0]
            related_entities = row[1].strip()
            if related_entities == "":
                related_entities = None
            terms[term_id] = related_entities
            source = row[2]
            if source not in sources:
                sources[source] = set()
            sources[source].add(term_id)
    first = True
    output = ""
    for source in sources:
        db = f"build/{source}.db"
        logging.info("Connecting to " + db)
        with sqlite3.connect(db) as conn:
            cur = conn.cursor()
            # Get all terms (using related entities) and export
            all_terms = set()
            for term_id, related_entities in terms.items():
                all_terms.add(term_id)
                if not related_entities:
                    continue
                if related_entities == "ancestors":
                    pass
                elif related_entities == "descendants":
                    pass
                elif related_entities == "parents":
                    pass
                elif related_entities == "children":
                    pass
                else:
                    abort(
                        400,
                        description=f"Unknown related entities selector for {term_id}: "
                        + related_entities,
                    )
        no_headers = True
        if first:
            no_headers = False
            first = False
        output += gizmos.export.export_terms(
            db,
            list(all_terms),
            properties,
            output_format,
            default_value_format="CURIE",
            no_headers=no_headers,
        )
    mt = "text/tab-separated-values"
    if output_format.lower() == "csv":
        mt = "text/comma-separated-values"
    resp = Response(output, mimetype=mt)
    resp.headers['Content-Disposition'] = f"attachment; filename={list_name}.{output_format.lower()}"
    return resp


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


def get_lists():
    lists = []
    for f in os.listdir("build/lists"):
        lists.append(os.path.splitext(f)[0])
    return lists


def get_tree(ns, term_id, message=""):
    db = get_database(ns)
    fmt = request.args.get("format", "")
    if fmt == "json":
        label = request.args.get("text", "")
        return gizmos.search.search(db, label, limit=30)

    href = "./{curie}"
    if ns not in browsers:
        return abort(500, description="Unknown ontology: " + ns)

    content = gizmos.tree.tree(db, term_id, title=browsers[ns], href=href)
    return render_template("tree.html", tree=content, lists=get_lists(), message=message)
