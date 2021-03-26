#!/usr/bin/env python3

import csv
import functools
import gizmos.export
import gizmos.search
import gizmos.tree
import logging
import os
import requests
import sqlite3
import subprocess

from collections import defaultdict
from flask import abort, Flask, g, redirect, render_template, request, Response, session, url_for
from sqlalchemy import create_engine, Column, Integer, MetaData, String, Table
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import parse_qs

# Note that the following environment variables must be set:
# DATABASE_URI
# GITHUB_CLIENT_ID
# GITHUB_CLIENT_SECRET
# GITHUB_APP_STATE
# FLASK_SECRET_KEY
# FLASK_HOST

# Initialize the logger:
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Check for environment variables, exit if any are missing
DATABASE_URI = os.environ.get("DATABASE_URI")
if not DATABASE_URI:
    raise Exception("DATABASE_URI must be specified")
GITHUB_APP_STATE = os.environ.get("GITHUB_APP_STATE")
if not GITHUB_APP_STATE:
    raise Exception("GITHUB_APP_STATE must be specified")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
if not GITHUB_CLIENT_ID:
    raise Exception("GITHUB_CLIENT_ID must be specified")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
if not GITHUB_CLIENT_SECRET:
    raise Exception("GITHUB_CLIENT_SECRET must be specified")
FLASK_HOST = os.environ.get("FLASK_HOST")
if not FLASK_HOST:
    raise Exception("FLASK_HOST must be specified")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    raise Exception("FLASK_SECRET_KEY must be specified")

# Set up the webapp
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Setup sqlalchemy to manage the database of logged in users
engine = create_engine(DATABASE_URI)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

# Check for tables and create them if they do not exist
meta = MetaData()
if not engine.dialect.has_table(engine, "users"):
    user_table = Table(
        "users",
        meta,
        Column("id", Integer, primary_key=True),
        Column("github_id", Integer),
        Column("github_login", String(255)),
    )
    meta.create_all(engine)
if not engine.dialect.has_table(engine, "lists"):
    lists_table = Table(
        "lists",
        meta,
        Column("id", Integer, primary_key=True),
        Column("user_id", Integer),
        Column("name", String(225)),
    )
    meta.create_all(engine)
if not engine.dialect.has_table(engine, "list_data"):
    lists_table = Table(
        "list_data",
        meta,
        Column("id", Integer, primary_key=True),
        Column("list_id", Integer),
        Column("term_id", String(225)),
        Column("source", String(225)),
        Column("related_entities", String(225)),
    )
    meta.create_all(engine)


BROWSERS = {
    # "chebi": "Chemical Entities of Biological Interest",
    "go": "Gene Ontology",
    "ncbitaxon": "NCBI Organismal Classification",
    "obi": "Ontology for Biomedical Investigations",
    "pato": "Phenotype And Trait Ontology",
    "so": "Sequence Ontology",
    "uo": "Units of Measurement Ontology",
    "uberon": "Uberon Multi-Species Anatomy Ontology",
}

# URLs and functions used for communicating with GitHub:
GITHUB_DEFAULT_API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "purl-editor/1.0",
}
GITHUB_API_URL = "https://api.github.com"
GITHUB_OAUTH_URL = "https://github.com/login/oauth"


# Decorators


def verify_logged_in(fn):
    """
    Decorator used to make sure that the user is logged in
    """
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        # If the user is not logged in, then redirect to the "index" page:
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapped


# Routes


@app.route("/")
def index():
    user_id = session.get("user_id")
    if user_id:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            logging.info(f"No user exists with ID {user_id}, logging out...")
            return redirect(url_for("logout"))
        return render_template("index.html", user=user.github_login)
    return render_template("index.html")


@app.route("/browser")
@verify_logged_in
def browser():
    html = "<h3>Select a set of terms to browse:</h3>\n"
    html += "  <ul>\n"
    for ns, title in BROWSERS.items():
        html += f'\n    <li><a href="/browser/{ns}/">{title}</a></li>\n'
    html += "  </ul>\n"
    return render_template("base.html", default=html, user=session.get("user_id"))


@app.route("/browser/<ns>/")
@verify_logged_in
def browse_ontology(ns):
    return render_tree(ns, None)


@app.route("/browser/<ns>/<term_id>", methods=["GET", "POST"])
@verify_logged_in
def browse_ontology_at(ns, term_id):
    message = ""
    user_id = session.get("user_id")
    if request.method == "POST":
        # Add the term to a list
        list_name = request.form["listName"]
        lst = List.query.filter_by(user_id=user_id, name=list_name).first()
        if not lst:
            return abort(400, f"List '{list_name}' does not exist for the current logged-in user!")

        related_entities = ",".join(request.form.getlist("relatedEntities"))
        list_data = ListData(lst.id, term_id, ns, related_entities)
        db_session.add(list_data)
        db_session.commit()

        message += '<div class="alert alert-success alert-dismissible fade show" role="alert">\n'
        message += f'<h5 class="alert-heading">{term_id} added to list "{list_name}"</h5>\n'
        message += '<p class="mb-0">When finished, return to <a href="/export">Export</a> to export or delete your list.</p>\n'
        message += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>\n'
        message += "</div>\n"
    return render_tree(ns, term_id, message=message)


@app.route("/export", methods=["GET", "POST"])
@verify_logged_in
def export():
    user_id = session.get("user_id")
    message = ""
    if request.method == "POST":
        # Either adding or deleting a list
        action = request.args.get("action")
        if action == "create":
            # Check for an existing list with this name for this user
            list_name = request.form["listName"]
            existing = List.query.filter_by(user_id=user_id, name=list_name).first()
            if existing:
                message += '<div class="alert alert-danger alert-dismissible" role="alert">'
                message += f'. <p class="mb-0">A list with the name "{list_name}" already exists. Please try again.</p>'
                message += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>\n'
                message += "</div>\n"
            else:
                lst = List(user_id, list_name)
                db_session.add(lst)
                db_session.commit()

                message += '<div class="alert alert-success alert-dismissible" role="alert">\n'
                message += (
                    f'<h5 class="alert-heading">New list created with name "{list_name}"</h3>\n'
                )
                message += '<p class="mb-0">You can now go to the <a href="/browser">Browser</a> to add terms to this list. '
                message += 'When finished, return to <a href="/export">Export</a> to export or delete your list.</p>\n'
                message += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>\n'
                message += "</div>\n"
        elif action == "delete":
            list_name = request.form.get("list")
            existing = List.query.filter_by(user_id=user_id, name=list_name).first()
            if existing:
                db_session.delete(existing)
                db_session.commit()
                message += '<div class="alert alert-success alert-dismissible" role="alert">\n'
                message += f'  <p class="mb-0">List "{list_name}" has been deleted</p>\n'
                message += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>\n'
                message += "</div>\n"
            else:
                # List does not exist, we cannot remove it - this should never happen!
                abort(400, f"List '{list_name}' does not exist for this user; unable to remove.")
        else:
            return abort(400, "Unknown action: " + action)
        redirect(url_for("export"))
    lists = get_user_lists()
    return render_template("export.html", lists=lists, user=user_id, message=message)


@app.route("/export/edit", methods=["GET", "POST"])
@verify_logged_in
def edit_list():
    list_name = request.args.get("list")
    if not list_name:
        # No list name provided, go back to export page
        redirect(url_for("export"))

    # Get the list items
    user_id = session.get("user_id")
    lst = List.query.filter_by(name=list_name, user_id=user_id).first()
    if not lst:
        return abort(400, f"List '{list_name}' does not exist for this user.")
    items = ListData.query.filter_by(list_id=lst.id)

    if request.method == "POST":
        import json

        # Get form data and update accordingly
        deleted_terms = []
        for itm in items:
            term_id = itm.term_id
            # Check if we are deleting this term
            delete_term = request.form.get(f"delete{term_id}")
            if delete_term:
                db_session.delete(itm)
                db_session.commit()
                deleted_terms.append(term_id)
                continue
            # Check if related entities has changed
            re_update = request.form.getlist(f"{term_id}relatedEntities")
            re_current = itm.related_entities
            if re_current:
                re_current = re_current.split(",")
            if set(re_update) != set(re_current):
                # Related entities have changed, update the value in database
                itm.related_entities = ",".join(re_update)
                db_session.commit()
        if deleted_terms:
            logging.info(f"Deleted terms from {list_name}: " + ", ".join(deleted_terms))
        # Requery to get updated items
        items = ListData.query.filter_by(list_id=lst.id)
        redirect(url_for("edit_list"))

    terms = []
    for itm in items:
        term = {
            "id": itm.term_id,
            "label": get_label(itm.source, itm.term_id),
            "source": itm.source,
        }
        if itm.related_entities:
            for re in itm.related_entities.split(","):
                term[re] = True
        logging.info(term)
        terms.append(term)
    return render_template("edit_list.html", list_name=list_name, terms=terms, user=user_id)


@app.route("/export/lists", methods=["GET", "POST"])
@verify_logged_in
def export_list():
    message = ""
    if request.method == "POST":
        list_name = request.form["listName"]
        properties = request.form.getlist("selectedProperties")
        output_format = request.form["formatOption"]
        return return_export(list_name, properties, output_format)
    return render_template(
        "export_list.html", lists=get_user_lists(), message=message, user=session.get("user_id")
    )


@app.route("/github_callback")
def github_callback():
    def fetch_access_token(args):
        temporary_code = args.get("code")
        params = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": temporary_code,
            "state": GITHUB_APP_STATE,
            "redirect_uri": f"{FLASK_HOST}/github_callback",
        }

        try:
            response = github_authorize_token(params)
        except requests.HTTPError as e:
            logger.error(e)
            return None

        content = parse_qs(response.text)
        access_token = content.get("access_token")
        if not access_token:
            logger.error("Could not retrieve access token")
            return None
        access_token = access_token[0]

        token_type = content.get("token_type")
        if not token_type:
            logger.error("No token type returned")
            return None
        token_type = token_type[0]
        if token_type.casefold() != "bearer":
            logger.error("Unexpected token type retrieved: " + token_type)
            return None

        return access_token

    if request.args.get("state") != GITHUB_APP_STATE:
        logging.error("Received wrong state. Aborting authorization due to possible CSRF attack.")
        return redirect("/logout")

    access_token = fetch_access_token(request.args)
    next_url = request.args.get("next") or url_for("index")
    if access_token is None:
        # If we don't receive a token, just redirect (an error message has already been logged)
        return redirect(next_url)

    github_user = github_call("GET", "/user", access_token)
    user = User.query.filter_by(github_id=github_user["id"]).first()
    if user is None:
        user = User(github_user["id"])
        db_session.add(user)
    else:
        logging.info(f"Logging in existing user with ID {user.id}")

    # Update login, in case it has changed
    user.github_login = github_user["login"]
    db_session.commit()

    # Add the user to the session
    session["user_id"] = user.id

    return redirect(next_url)


@app.route("/logout")
def logout():
    if session.get("user_id"):
        session.pop("user_id")
    return redirect(url_for("index"))


@app.route("/login")
def login():
    if session.get("user_id") is not None:
        session.pop("user_id")

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "state": GITHUB_APP_STATE,
        "redirect_uri": f"{FLASK_HOST}/github_callback",
    }
    try:
        response = github_authorize(params)
        return redirect(response.url)
    except requests.HTTPError as e:
        logger.error(e)
        return redirect(url_for("logout"))


# Methods


def get_ancestors(cur, node):
    cur.execute(
        """WITH RECURSIVE ancestors(node) AS (
        VALUES (?)
        UNION
         SELECT object AS node
        FROM statements
        WHERE predicate = 'rdfs:subClassOf'
          AND object = ?
        UNION
        SELECT object AS node
        FROM statements, ancestors
        WHERE ancestors.node = statements.stanza
          AND statements.predicate = 'rdfs:subClassOf'
          AND statements.object NOT LIKE '_:%'
      )
      SELECT * FROM ancestors""",
        (node, node),
    )
    return set([x[0] for x in cur.fetchall()])


def get_children(cur, node):
    cur.execute(
        """SELECT DISTINCT stanza FROM statements
           WHERE predicate = 'rdfs:subClassOf' AND object = ?""",
        (node,),
    )
    return set([x[0] for x in cur.fetchall()])


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


def get_descendants(cur, node):
    cur.execute(
        """WITH RECURSIVE descendants(node) AS (
        VALUES (?)
        UNION
         SELECT stanza AS node
        FROM statements
        WHERE predicate = 'rdfs:subClassOf'
          AND stanza = ?
        UNION
        SELECT stanza AS node
        FROM statements, descendants
        WHERE descendants.node = statements.object
          AND statements.predicate = 'rdfs:subClassOf'
      )
      SELECT * FROM descendants""",
        (node, node),
    )
    return set([x[0] for x in cur.fetchall()])


def get_label(source, node):
    db = f"build/{source}.db"
    with sqlite3.connect(db) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT value FROM statements WHERE subject = ? AND predicate = 'rdfs:label'", (node,)
        )
        res = cur.fetchone()
        if res:
            return res[0]
    return ""


def get_parents(cur, node):
    cur.execute(
        """SELECT DISTINCT object FROM statements
           WHERE stanza = ? AND predicate = 'rdfs:subClassOf'
           AND object IS NOT LIKE '_:%'""",
        (node,)
    )
    return set([x[0] for x in cur.fetchall()])


def get_user_lists():
    user_id = session.get("user_id")
    if not user_id:
        return []
    lists = List.query.filter_by(user_id=user_id)
    names = []
    for lst in lists:
        names.append(lst.name)
    return names


def github_call(method, endpoint, access_token, params={}):
    """
    Call the GitHub REST API at the given endpoint using the given method and passing the given
    params.
    """
    method = method.casefold()
    if method not in ["get", "post", "put"]:
        logger.error(f"Unsupported API method: {method}")
        return {}

    api_headers = GITHUB_DEFAULT_API_HEADERS
    api_headers["Authorization"] = f"token {access_token}"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    fargs = {"url": GITHUB_API_URL + endpoint, "headers": api_headers, "json": params}
    if method == "get":
        # GET parameters must go in URL - https://developer.github.com/v3/#parameters
        if len(params) > 0:
            fargs["url"] = fargs["url"] + "?" + urlencode(params)
        response = requests.get(**fargs)
    elif method == "post":
        response = requests.post(**fargs)
    elif method == "put":
        response = requests.put(**fargs)

    if not response.ok:
        if response.status_code == 403:
            logger.error(
                f"Received 403 Forbidden from {method} request to endpoint {endpoint}"
                "with params {params}"
            )
        response.raise_for_status()
    return response.json()


def github_authorize(params):
    response = requests.get(GITHUB_OAUTH_URL + "/authorize", params)
    if not response.ok:
        response.raise_for_status()
    return response


def github_authorize_token(params):
    response = requests.post(GITHUB_OAUTH_URL + "/access_token", params)
    if not response.ok:
        response.raise_for_status()
    return response


def render_tree(ns, term_id, message=""):
    db = get_database(ns)
    fmt = request.args.get("format", "")
    if fmt == "json":
        label = request.args.get("text", "")
        return gizmos.search.search(db, label, limit=30)

    href = "./{curie}"
    if ns not in BROWSERS:
        return abort(500, description="Unknown ontology: " + ns)

    content = gizmos.tree.tree(db, term_id, title=BROWSERS[ns], href=href, standalone=False)
    return render_template(
        "tree.html",
        tree=content,
        lists=get_user_lists(),
        message=message,
        user=session.get("user_id"),
    )


def return_export(list_name, properties, output_format):
    """
    Return a response containing the exported list for download.
    """
    user_id = session.get("user_id")
    lst = List.query.filter_by(name=list_name, user_id=user_id).first()
    if not lst:
        return abort(400, description=f"List does not exist: " + list_name)

    sources = defaultdict(set)
    terms = {}
    items = ListData.query.filter_by(list_id=lst.id)
    for itm in items:
        term_id = itm.term_id
        related_entities = itm.related_entities
        terms[term_id] = related_entities
        source = itm.source
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
                    all_terms.update(get_ancestors(cur, term_id))
                elif related_entities == "descendants":
                    all_terms.update(get_descendants(cur, term_id))
                elif related_entities == "parents":
                    all_terms.update(get_parents(cur, term_id))
                elif related_entities == "children":
                    all_terms.update(get_children(cur, term_id))
                else:
                    return abort(
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
    resp.headers[
        "Content-Disposition"
    ] = f"attachment; filename={list_name}.{output_format.lower()}"
    return resp


# Classes


class User(Base):
    """
    Saved information for users that have been authenticated to the metadata editor.
    Note that this table preserves historical data (data is not deleted on logout)
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    github_id = Column(Integer)
    github_login = Column(String(255))

    def __init__(self, github_id):
        self.github_id = github_id


class List(Base):
    """
    Saved information for export lists for users.
    """

    __tablename__ = "lists"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    name = Column(String(255))

    def __init__(self, user_id, name):
        self.user_id = user_id
        self.name = name


class ListData(Base):
    """
    Saved information for the terms within export lists.
    """

    __tablename__ = "list_data"

    id = Column(Integer, primary_key=True)
    list_id = Column(Integer)
    term_id = Column(String(255))
    source = Column(String(255))
    related_entities = Column(String(255))

    def __init__(self, list_id, term_id, source, related_entities):
        self.list_id = list_id
        self.term_id = term_id
        self.source = source
        self.related_entities = related_entities
