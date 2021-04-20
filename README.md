# demo
A demonstration of the range of OntoDev tools

## Running the Demo

In order to run this app, you must first create a [GitHub App](https://docs.github.com/en/developers/apps/about-apps). When setting up your GitHub App, set the **Callback URL** to `HOST/github_callback` where `HOST` is replaced with wherever you're running this (Flask defaults to `localhost:5000`, so this will most likely be `http://localhost:5000/github_callback`). Also check the box that says **Request user authorization (OAuth) during installation**.

Once created, you need to generate a new client secret and a new private key. Copy the client secret to somewhere safe and save the private key `.pem` file to a location of your choice.

Before starting the demo, set the following environment variables:
* `DATABASE_URI`: path to the SQLite database that backs the application; this should start with `sqlite:///` followed by the absolute path, e.g. `sqlite:////tmp/test.db`).
* `DROID_PATH`: path to the DROID directory to use for the base versions of resources, including all databases
* `GITHUB_APP_STATE`: an unguessable random string used to protect against cross-site request forgery attacks.
* `GITHUB_CLIENT_ID`: the client ID of your GitHub App, which can be found in the **About** section of the app settings.
* `GITHUB_CLIENT_SECRET`: the client secret you generated after setting up your GitHub App (the string itself, not a path to a file containing the secret).
* `GITHUB_PRIVATE_KEY`: the path to the `.pem` file you saved after setting up your GitHub App.
* `FLASK_SECRET_KEY`: an unguessable random string used for Flask encryption.
* `FLASK_HOST`: where the Flask app is running (the default is `http://localhost:5000`).
* `OBI_BASE_BRANCH`: the OBI branch from which to retrieve resources and create new branches from.
* `OBI_REPO`: the name of the obi repository in format `ORG_OR_USER/NAME` (e.g., `obi-ontology/obi`).

Now you can run the demo:

```
export FLASK_APP=src/run.py
flask run
```

This will start the Flask server on port `5000`, unless you have specified differently. Make sure whichever port you're running on matches the GitHub App configuration.

The first time the Flask app starts, it will need to retrieve all resources from the base OBI branch. Because there are some large databases, this may take some time. Watch for log messages on the console to monitor your progress.
