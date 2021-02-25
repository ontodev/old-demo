### GNU Make Configuration
#
# These are standard options to make Make sane:
# <http://clarkgrubb.com/makefile-style-guide#toc2>

MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SUFFIXES:
.SECONDARY:


ONTS := go ncbitaxon obi pato so uo uberon # chebi 


### Set Up

build:
	mkdir $@

cache:
	mkdir $@

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	RDFTAB_URL := https://github.com/ontodev/rdftab.rs/releases/download/v0.1.1/rdftab-x86_64-apple-darwin
	SED = sed -i.bak
else
	RDFTAB_URL := https://github.com/ontodev/rdftab.rs/releases/download/v0.1.1/rdftab-x86_64-unknown-linux-musl
	SED = sed -i
endif

build/rdftab: | build
	curl -L -o $@ $(RDFTAB_URL)
	chmod +x $@


### Databases

DBS := $(foreach O,$(ONTS),build/$(O).db)
dbs: $(DBS)

build/%.owl: | build
	curl -Lk "http://purl.obolibrary.org/obo/$(notdir $@)" > $@

build/%.db: src/prefixes.sql build/%.owl | build/rdftab
	rm -rf $@
	sqlite3 $@ < $<
	./build/rdftab $@ < $(word 2,$^)
	sqlite3 $@ "CREATE INDEX idx_stanza ON statements (stanza);"
	sqlite3 $@ "CREATE INDEX idx_subject ON statements (subject);"
	sqlite3 $@ "CREATE INDEX idx_predicate ON statements (predicate);"
	sqlite3 $@ "CREATE INDEX idx_object ON statements (object);"
	sqlite3 $@ "CREATE INDEX idx_value ON statements (value);"
	sqlite3 $@ "ANALYZE;"


### Main tasks

all: dbs

clean:
	rm build/*.db

clobber:
	rm -rf build
