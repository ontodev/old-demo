# demo
A demonstration of the range of OntoDev tools

## Setup

First, install the requirements:

```
python3 -m pip install -r requirements.txt
```

Then, build the SQLite databases required to run the demo:

```
make all
```

The first time you run `make all` may take a bit of time, as we need to download a handful of ontologies, including some large ones such as NCBITaxonomy and UBERON. Once this is done once and you have the `build/` directory, you can rebuild the SQLite databases using `make clean all`. This will not re-download the ontologies. If you wish to re-download and re-build everything, use `make clobber all`.

Currently, the following ontologies are included in the demo:
* Chemical Entities of Biological Interest (ChEBI)
* Gene Ontology (GO)
* NCBI Organismal Classification (NCBITaxon)
* Ontology for Biomedical Investigations (OBI)
* Phenotype and Trait Ontology (PATO)
* Sequence Ontology (SO)
* Units of Measurement Ontology (UO)
* Uberon Multi-Species Anatomy Ontology (UBERON)

## Running the Demo

To run the demo, simply set the Flask app path and run it:

```
export FLASK_APP=src/run.py
flask run
```

This will start the Flask server on port `5000`, unless you have specified differently.
