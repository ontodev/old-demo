#!/usr/bin/env python3

import csv
import functools
import gizmos.search
import gizmos.tree
import json
import jwt
import logging
import os
import requests
import sqlite3

from collections import defaultdict
from datetime import date, datetime, timezone
from flask import abort, Flask, g, redirect, render_template, request, Response, session, url_for
from github import Github
from github.GithubException import GithubException
from sqlalchemy import create_engine, Column, Integer, MetaData, String, Table
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import parse_qs

# Note that the following environment variables must be set:
# DATABASE_URI
# GITHUB_APP_ID
# GITHUB_APP_STATE
# GITHUB_CLIENT_ID
# GITHUB_CLIENT_SECRET
# GITHUB_PRIVATE_KEY
# FLASK_SECRET_KEY
# FLASK_HOST
# OBI_BASE_BRANCH
# OBI_REPO

# Initialize the logger:
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Check for environment variables, exit if any are missing
DATABASE_URI = os.environ.get("DATABASE_URI")
if not DATABASE_URI:
    raise Exception("DATABASE_URI must be specified")
DROID_PATH = os.environ.get("DROID_PATH")
if not DROID_PATH:
    raise Exception("DROID_PATH must be specified")
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID")
if not GITHUB_APP_ID:
    raise Exception("GITHUB_APP_ID must be specified")
GITHUB_APP_STATE = os.environ.get("GITHUB_APP_STATE")
if not GITHUB_APP_STATE:
    raise Exception("GITHUB_APP_STATE must be specified")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
if not GITHUB_CLIENT_ID:
    raise Exception("GITHUB_CLIENT_ID must be specified")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
if not GITHUB_CLIENT_SECRET:
    raise Exception("GITHUB_CLIENT_SECRET must be specified")
GITHUB_PRIVATE_KEY = os.environ.get("GITHUB_PRIVATE_KEY")
if not GITHUB_PRIVATE_KEY:
    raise Exception("GITHUB_PRIVATE_KEY must be specified")
FLASK_HOST = os.environ.get("FLASK_HOST")
if not FLASK_HOST:
    raise Exception("FLASK_HOST must be specified")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    raise Exception("FLASK_SECRET_KEY must be specified")
OBI_BASE_BRANCH = os.environ.get("OBI_BASE_BRANCH")
if not OBI_BASE_BRANCH:
    raise Exception("OBI_BASE_BRANCH must be specified")
OBI_REPO = os.environ.get("OBI_REPO")
if not OBI_REPO:
    raise Exception("OBI_REPO must be specified")

# URLs and functions used for communicating with GitHub:
GITHUB_DEFAULT_API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "obi-demo/1.0",
}
GITHUB_API_URL = "https://api.github.com"
GITHUB_OAUTH_URL = "https://github.com/login/oauth"

# DROID paths to fetch resources
DATABASE_DIR = os.path.join(DROID_PATH, "build")
IMPORTS_DIR = os.path.join(DROID_PATH, "src/ontology/imports")
TEMPLATES_DIR = os.path.join(DROID_PATH, "src/ontology/templates")

# Import source databases
IMPORTS = {
    "chebi": "Chemical Entities of Biological Interest",
    "cl": "Cell Ontology",
    "clo": "Cell Line Ontology",
    "envo": "Environment Ontology",
    "go": "Gene Ontology",
    "hp": "Human Phenotype Ontology",
    "ido": "Infectious Disease Ontology",
    "ncbitaxon": "NCBI Organismal Classification",
    "ogms": "Ontology for General Medical Science",
    "omiabis": "Organized MIABIS",
    "omrse": "Ontology of Medically Related Social Entities",
    "pato": "Phenotype and Trait Ontology",
    "pr": "Protein Ontology",
    "so": "Sequence Ontology",
    "uberon": "Uberon Multi-Species Anatomy Ontology",
    "uo": "Units of Measurement Ontology",
    "vo": "Vaccine Ontology",
}

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
    logging.info("Creating 'users' table...")
    user_table = Table(
        "users",
        meta,
        Column("id", Integer, primary_key=True),
        Column("github_id", Integer),
        Column("github_login", String(255)),
        Column("access_token", String(255)),
    )
    meta.create_all(engine)
if not engine.dialect.has_table(engine, "changes"):
    logging.info("Creating 'changes' table...")
    changes_table = Table(
        "changes",
        meta,
        Column("id", Integer, primary_key=True),
        Column("user_id", Integer),
        Column("file", String(255)),
        Column("file_type", String(255)),
    )
    meta.create_all(engine)

# Make sure we have the build directory
if not os.path.exists("build"):
    os.mkdir("build")


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


# ------------------------------- MAIN APP ROUTES -------------------------------


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


@app.route("/add-term/<template>")
@verify_logged_in
def add_term(template):
    message = ""
    if request.args.get("add"):
        user_id = session.get("user_id")
        message = add_to_template(user_id, template, request.args)
    return build_template(template, message=message)


@app.route("/browse")
@verify_logged_in
def browse_obi():
    return render_tree("obi", None)


@app.route("/browse/<term_id>")
@verify_logged_in
def browse_obi_at(term_id):
    return render_tree("obi", term_id)


@app.route("/import/<ns>")
@verify_logged_in
def browse_import(ns):
    return render_tree(ns, None, is_import=True)


@app.route("/import/<ns>/<term_id>")
@verify_logged_in
def browse_import_at(ns, term_id):
    message = ""
    if request.args.get("add"):
        user_id = session.get("user_id")
        message = add_to_import(user_id, ns, term_id, request.args)
    return render_tree(ns, term_id, message=message, is_import=True)


@app.route("/search")
@verify_logged_in
def search():
    text = request.args.get("text", "")
    ns = request.args.get("db")
    if not ns:
        abort(400, "A db parameter is required for search")
    db = os.path.join(DATABASE_DIR, ns + ".db")
    if not os.path.exists(db):
        abort(500, f"A database for {ns} does not exist")
    conn = sqlite3.connect(db)
    return gizmos.search.search(conn, text, limit=30)


@app.route("/submit")
@verify_logged_in
def submit():
    user_id = session["user_id"]
    if request.args.get("submit", ""):
        user = User.query.filter_by(id=user_id).first()
        inst_token = get_installation_token()
        repo = get_repo(inst_token)

        # Create a new branch (github login + date)
        now = date.today().strftime("%Y-%m-%d")
        branch_name = f"{user.github_login}-{now}"

        # Check if this branch already exists
        try:
            this_branch = repo.get_branch(branch=branch_name)
        except GithubException:
            this_branch = None

        if this_branch:
            # Add the time to the branch name
            now = datetime.now().strftime("%Y-%m-%d-%H%M")
            branch_name = f"{user.github_login}-{now}"

        # Get the base branch to branch off of
        try:
            base = repo.get_branch(branch=OBI_BASE_BRANCH)
        except GithubException:
            abort(500, f"'{OBI_BASE_BRANCH} does not exist in repo {OBI_REPO}")
        logging.info(f"Creating branch {branch_name} from {OBI_BASE_BRANCH}")
        repo.create_git_ref(ref="refs/heads/" + branch_name, sha=base.commit.sha)

        # Programmatically commit changes to the files
        updated_files = commit_changes(user_id, repo, branch_name)

        # Create a new pull request
        body = ["Update files:", ""]
        for uf in updated_files:
            body.append("- " + uf)

        # Switch to user access token for PR (app can't create PRs)
        repo = get_repo(user.access_token)
        title = request.args.get("prName") or branch_name
        pr = repo.create_pull(
            title=title, body="\n".join(body), head=branch_name, base=OBI_BASE_BRANCH
        )

        html = f'<a href="https://github.com/{OBI_REPO}/pull/{pr.number}">Go to pull request</a>'
        return render_template("base.html", default=html, user=True)

    # Display a list of changed files with option to submit a new PR
    changed_files = get_changed_files(user_id)
    return render_template("submit.html", changes=changed_files, user=True)


# ------------------------------- GITHUB APP ROUTES -------------------------------


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

    # Update login & token, in case it has changed
    user.github_login = github_user["login"]
    user.access_token = access_token
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


# ------------------------------- HELPER METHODS -------------------------------


def add_to_import(user_id, ns, term_id, args):
    """Add a new term to an import file based on the request args provided."""
    user_dir = "build/" + str(user_id)
    if not os.path.exists(user_dir):
        os.mkdir(user_dir)

    db = os.path.join(DATABASE_DIR, ns + ".db")
    if not os.path.exists(db):
        abort(500, f"A database for {ns} does not exist")
    message = ""
    with sqlite3.connect(db) as conn:
        # Get a label to display in import file
        label = ""
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT value FROM statements WHERE stanza = ? AND predicate = 'rdfs:label'",
            (term_id,),
        )
        res = cur.fetchone()
        if res:
            label = res[0]

        # Check for an override parent - this must be a label and must exist in OBI
        parent = args.get("parent", "")
        parent_label = ""
        if parent:
            obi_db = os.path.join(DATABASE_DIR, "obi.db")
            if not os.path.exists(obi_db):
                abort(500, "A database for obi does not exist")
            with sqlite3.connect(obi_db) as obi_conn:
                obi_cur = obi_conn.cursor()
                obi_cur.execute(
                    """SELECT DISTINCT stanza FROM statements
                       WHERE predicate = 'rdfs:label' AND value = ?""",
                    (parent,),
                )
                res = obi_cur.fetchone()
                if res:
                    parent_label = res[0]

    if parent and not parent_label:
        return build_message(
            "danger",
            f"'{label}' ({term_id}) could not be added; parent '{parent}' does not exist in OBI.",
        )

    # Check for related entities
    related = args.get("relatedEntities", "")
    if related:
        if related.startswith("["):
            related = related[1:-1].replace('"', "")
    if not parent and "ancestors" not in related:
        # If no parent was provided, we need to include ancestors in order to place the term
        related += " ancestors"
        related = related.lstrip()

    # If a user import file exists, the user has already updated this file
    # Otherwise use the base file and write a new user import file
    base_import_file = os.path.join(IMPORTS_DIR, ns + "_terms.tsv")
    user_import_file = f"{user_dir}/{ns}_terms.tsv"
    import_file = base_import_file
    if os.path.exists(user_import_file):
        import_file = user_import_file

    # Get rows while checking if this term already exists
    rows = []
    with open(import_file, "r") as f:
        exists = False
        reader = csv.DictReader(f, delimiter="\t")
        headers = reader.fieldnames
        for row in reader:
            existing_id = row["ID"]
            if term_id == existing_id:
                exists = True
                break
            rows.append(row)
    if exists:
        return build_message("warning", f"'{label}' ({term_id}) already exists in {db} import.")

    rows.append(
        {
            "Source": ns,
            "ID": term_id,
            "Label": label,
            "Parent ID": parent,
            "Parent Label": parent_label,
            "Related": related,
        }
    )

    # Always write to the user's version of the import file
    with open(user_import_file, "w") as f:
        logging.info(headers)
        writer = csv.DictWriter(f, delimiter="\t", lineterminator="\n", fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    # Log the change so we know what was updated (if it's already been logged, do nothing)
    change = Change.query.filter_by(user_id=user_id, file=f"{ns}_terms.tsv").first()
    if not change:
        change = Change(user_id, f"{ns}_terms.tsv", "import")
        db_session.add(change)
        db_session.commit()

    return build_message("success", f"'{label}' ({term_id}) added to {db} import!")


def add_to_template(user_id, template, args):
    """Add a new term to the given template based on the request args provided."""
    user_dir = "build/" + str(user_id)
    if not os.path.exists(user_dir):
        os.mkdir(user_dir)

    term_id = args["ontology-ID"]
    term_label = args["label"]

    # If a user template file exists, the user has already updated this file
    # Otherwise use the base file and write a new user template file
    base_template_file = os.path.join(TEMPLATES_DIR, template + ".tsv")
    user_template_file = f"{user_dir}/{template}.tsv"
    template_file = base_template_file
    if os.path.exists(user_template_file):
        template_file = user_template_file

    rows = []
    with open(template_file, "r") as f:
        reader = csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE, escapechar='"')
        headers = reader.fieldnames
        for row in reader:
            if row["ontology ID"] == term_id:
                existing_label = row["label"]
                return build_message(
                    "danger",
                    f"Cannot add '{term_label}' ({term_id}) to {template} template; "
                    + f"{term_id} already exists in template as '{existing_label}'.",
                )
            rows.append(row)

    add_row = {}
    bad = []
    for header, value in args.items():
        header = header.replace("-", " ")
        if header not in headers:
            bad.append(header)
            continue
        add_row[header] = value
    rows.append(add_row)

    logging.warning(f"Found {len(bad)} incorrect headers: " + ", ".join(bad))

    # Log the change so we know what was updated (if it's already been logged, do nothing)
    change = Change.query.filter_by(user_id=user_id, file=template + ".tsv").first()
    if not change:
        change = Change(user_id, template + ".tsv", "template")
        db_session.add(change)
        db_session.commit()

    # Sort rows by ID
    robot_template = rows.pop(0)
    rows.sort(key=lambda x: x["ontology ID"])
    rows.insert(0, robot_template)

    # Always write to the user's version of the template file
    with open(user_template_file, "w") as f:
        logging.info(headers)
        writer = csv.DictWriter(f, delimiter="\t", lineterminator="\n",  quoting=csv.QUOTE_NONE, escapechar='"', fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    return build_message(
        "success", f"Successfully added '{term_label}' ({term_id}) to {template} template!"
    )


def build_form_field(input_type, column, help_msg, required):
    """Return an HTML form field for a template field."""
    if required:
        display = column + " *"
    else:
        display = column

    html = []
    html.append('<div class="row mb-3">')
    html.append(f'\t<label class="col-sm-2 col-form-label">{display}</label>')
    html.append('\t<div class="col-sm-10">')

    field_name = column.replace(" ", "-")

    if input_type == "text":
        if required:
            html.append(
                f'\t\t<input type="text" class="form-control" name="{field_name}" required>'
            )
            html.append('\t\t<div class="invalid-feedback">')
            html.append(f"\t\t\t{column} is required")
            html.append("</div>")
        else:
            html.append(f'\t\t<input type="text" class="form-control" name="{field_name}">')

    elif input_type == "textarea":
        if required:
            html.append(
                f'\t\t<textarea class="form-control" name="{field_name}" rows="3" required></textarea>'
            )
            html.append('\t\t<div class="invalid-feedback">')
            html.append(f"\t\t\t{column} is required")
            html.append("</div>")
        else:
            html.append(
                f'\t\t<textarea class="form-control" name="{field_name}" rows="3"></textarea>'
            )

    elif input_type == "search":
        if required:
            html.append(
                f'<input type="text" class="searc form-control" name="{field_name}" id="{field_name}-typeahead-obi" required>'
            )
            html.append('\t\t<div class="invalid-feedback">')
            html.append(f"\t\t\t{column} is required")
            html.append("</div>")
        else:
            html.append(
                f'<input type="text" class="typeahead form-control" name="{field_name}" id="{field_name}-typeahead-obi">'
            )

    elif input_type.startswith("select"):
        selects = input_type.split("(", 1)[1].rstrip(")").split(", ")
        html.append(f'\t\t<select class="form-select" name="{field_name}">')
        for s in selects:
            html.append(f'\t\t\t<option value="{s}">{s}</option>')
        html.append("\t\t</select>")

    else:
        return None

    if help_msg:
        html.append(f'\t\t<div class="form-text">{help_msg}</div>')
    html.append("\t</div>")
    html.append("</div>")
    return html


def build_message(message_type, message_content):
    """Return a pop-up message to display at the top of the page."""
    message = f'<div class="alert alert-{message_type} alert-dismissible fade show" role="alert">\n'
    message += f'<p class="mb-0">{message_content}</p>\n'
    message += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>\n'
    message += "</div>\n"
    return message


def build_template(template, message=""):
    """Build an HTML form template from the template fields."""
    metadata_fields = {}
    logic_fields = {}
    with open("src/field.tsv", "r") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            tables = row.get("table", "").split("|")
            if (not tables or template not in tables) and tables[0] != "*":
                continue
            column = row.get("column")
            if not column:
                continue
            category = row.get("category")
            if category == "metadata":
                metadata_fields[column] = {
                    "type": row.get("input type").strip(),
                    "help": row.get("help", "").strip(),
                    "required": bool(row.get("required", "false").strip()),
                }
            else:
                logic_fields[column] = {
                    "type": row.get("input type").strip(),
                    "help": row.get("help", "").strip(),
                    "required": bool(row.get("required", "false").strip()),
                }

    metadata_html = []
    for column, details in metadata_fields.items():
        input_type = details["type"]
        form_field = build_form_field(input_type, column, details["help"], details["required"])
        if not form_field:
            abort(500, f"Unknown input type '{input_type}' for column '{column}'")
        metadata_html.extend(form_field)

    logic_html = []
    for column, details in logic_fields.items():
        input_type = details["type"]
        form_field = build_form_field(input_type, column, details["help"], details["required"])
        if not form_field:
            abort(500, f"Unknown input type '{input_type}' for column '{column}'")
        logic_html.extend(form_field)

    return render_template(
        "add-term.html",
        title=f"New '{template}' Term",
        metadata="\n".join(metadata_html),
        logic="\n".join(logic_html),
        message=message,
        user=True
    )


def commit_changes(user_id, repo, branch_name):
    """Commit all logged changes to a branch in a repository."""
    changes = Change.query.filter_by(user_id=user_id)
    updated_files = []
    for c in changes:
        if c.file_type == "import":
            repo_path = "src/ontology/imports/" + c.file
        elif c.file_type == "template":
            repo_path = "src/ontology/templates/" + c.file
        else:
            # TODO - error?
            continue
        with open(f"build/{user_id}/{c.file}", "r") as f:
            content = f.read()

        logging.info("Updating " + repo_path)
        cur_file = repo.get_contents(repo_path, ref="refs/heads/" + OBI_BASE_BRANCH)

        # TODO - these commits all come from the app, not the user
        # is this a problem? When using the user access token,
        # it says resource not available
        repo.update_file(
            path=repo_path,
            message="Update " + c.file,
            content=content,
            sha=cur_file.sha,
            branch=branch_name,
        )

        # Remove record from table
        db_session.delete(c)
        db_session.commit()
        updated_files.append(repo_path)

        # Delete file from user dir
        os.remove(f"build/{user_id}/{c.file}")
    return updated_files


def get_changed_files(user_id):
    """Get all changed files for a user from the 'changes' table."""
    changes = Change.query.filter_by(user_id=user_id)
    if not changes:
        return []

    changed_files = []
    for c in changes:
        if c.file_type == "import":
            changed_files.append("src/ontology/imports/" + c.file)
        elif c.file_type == "template":
            changed_files.append("src/ontology/templates/" + c.file)
    return changed_files


def get_installation_token():
    """Generate a GitHub installation token which can be used for read/write access to the repo."""
    payload = {
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc)).timestamp()) + (10 * 60),
        "iss": GITHUB_APP_ID,
    }

    # Create the json web key
    with open(GITHUB_PRIVATE_KEY, "rb") as f:
        secret = f.read()
    jwk = jwt.encode(payload, secret, algorithm="RS256")

    # Retreived the installation ID for this user for this app
    r = requests.get(
        "https://api.github.com/app/installations",
        headers={"Authorization": "Bearer " + jwk, "Accept": "application/vnd.github.v3+json"},
    )
    data = json.loads(r.content)
    if not data:
        abort(500, "Unable to retrieve GitHub installation ID")
    try:
        data = data[0]
    except KeyError:
        pass

    installation_id = data.get("id")
    if not installation_id:
        msg = data.get("message", "cause unknown")
        abort(500, "Unable to retrieve GitHub installation ID: " + msg)

    # Use the installation ID to retrieve the installation token
    r = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={"Authorization": "Bearer " + jwk, "Accept": "application/vnd.github.v3+json"},
    )
    data = json.loads(r.content)
    token = data.get("token")
    if not token:
        msg = data.get("message", "cause unknown")
        abort(500, "Unable to retrieve GitHub installation token: " + msg)
    return token


def get_repo(token):
    """Create the Github object for the target repository."""
    api = Github(token)
    repo = api.get_repo(OBI_REPO)
    return repo


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


def render_tree(ns, term_id, message="", is_import=False):
    """Render the HTML tree for a given term (or top level, when term_id is None)."""
    db = os.path.join(DATABASE_DIR, ns + ".db")
    if not os.path.exists(db):
        abort(500, f"A database for {ns} does not exist")
    conn = sqlite3.connect(db)

    base = "browse"
    if is_import:
        base = ns
    if not term_id:
        href = base + "/{curie}"
    else:
        href = "./{curie}"
    if ns != "obi" and ns not in IMPORTS:
        abort(400, description="Unknown ontology: " + ns)

    title = IMPORTS.get(ns, "Ontology for Biomedical Investigations")

    content = gizmos.tree.tree(conn, ns, term_id, title=title, href=href, standalone=False)
    template_name = "tree.html"
    if is_import:
        template_name = "import.html"
    return render_template(
        template_name,
        ns=ns,
        tree=content,
        message=message,
        user=session.get("user_id"),
    )


# ------------------------------- SQLALCHEMY CLASSES -------------------------------


class User(Base):
    """
    Saved information for users that have been authenticated to the metadata editor.
    Note that this table preserves historical data (data is not deleted on logout)
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    github_id = Column(Integer)
    github_login = Column(String(255))
    access_token = Column(String(255))

    def __init__(self, github_id):
        self.github_id = github_id


class Change(Base):
    """
    Saved information on changed files. This data is erased after submitting a new PR.
    """

    __tablename__ = "changes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    file = Column(String(255))
    file_type = Column(String(255))

    def __init__(self, user_id, file, file_type):
        self.user_id = user_id
        self.file = file
        self.file_type = file_type


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
