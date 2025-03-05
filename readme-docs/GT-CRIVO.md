# GT-CRIVO DefectDojo extensions

Our project has made three main extensions to DefectDojo.  A key requirement our extensions support is that they make *zero* changes to DefectDojo's models or database; this ensures that any deployment using our extensions can be trivially reverted to a vanilla DefectDojo deployment by just changing the codebase.

1. The ability to group `Findings` into `Problems`.  Our extension receives as input any mapping of `Findings` to `Problems`; one of which we have built using Artificial Intelligence to analyze the detection scripts used by scanning techniques.

2. The ability for analysts to specify the priority of a vulnerability (a `Vote`).  This is integrated with Dojo's interface, and the information used to train the vulnerability prioritization model developed in the project. `Vote`s are stored in a separate SQLite database.

3. Integration of complementary metadata which to aid analysts investigate and troubleshoot a `Finding`.  The metadata are downloaded directly from [authoritative](https://www.first.org/epss/) [sources](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and shown in Dojo's `Finding` view.  Some of the metadata we integrate [are also available as a paid feature in Dojo's Pro subscription](https://github.com/DefectDojo/django-DefectDojo/discussions/11796), which helps illustrate their usefulness.

> A `Finding` is DefectDojo's terminology for any result (or "finding") reported by any of the integrated tools.  A `Finding` is somewhat of a catch-all structure given the wide spectrum of tools supported by DefectDojo, whose results are all stored in the same `Finding` class.  In the context of our project, `Finding`s come from network vulnerability scanners like Nuclei, Nmap, and OpenVAS.

## Installation

Installation of our extensions follows the [normal installation procedure for DefectDojo](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md).  You should just follow the installation procedure on top of [our development branch](https://github.com/LeoOMaia/django-DefectDojo/tree/redis-problems).  (TODO: link to release on RNP's Git.)  We frequently rebase our changes on top of Dojo's `master` branch to keep up to date with fixes and improvements on the platform, which also make it easy to check [the changes we have made to the code](https://github.com/DefectDojo/django-DefectDojo/compare/master...LeoOMaia:django-DefectDojo:redis-problems).  (TODO: link to diff in RNP's Git.)

## Configuration

The development branch is already preconfigured to run Dojo with the default configuration for our extensions.  Following Dojo's installation procedure on top of our branch should get you a working deployment with the extensions preconfigured.  The information below is provided as documentation.

We inject the configuration inside Dojo's running container by mounting a Docker volume inside the container.  The volume configuration is inside Dojo's `docker-compose.yml` file (TODO: permalink), and mounts the `crivo-metadata` directory inside our branch at `/app/crivo-metadata` inside the container.

The configuration parameters below are provided inside Dojo's (actually Django's) `local_settings.py` file. (TODO: permalink)  The required files mentioned in the subsections below are already added to the `crivo-metadata` directory (TODO), and pointed to by the `local_settings.py`

### `Problem` Mappings

`Finding` to `Problem` mappings should be provided as either an `https` or `file` URL in the `PROBLEM_MAPPINGS_JSON_URL` configuration variable. If this variable is not provided, the `Problem` tab will simply not show up in the interface, maintaining to Dojo's default functionality.

The mapping generated in the project is available over `HTTPS` and can be configured as follows. Our mapping groups `Findings` from Nmap, OpenVAS, Nuclei, and Metasploit.

```python
PROBLEM_MAPPINGS_JSON_URL = "https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json"
```

A local `file` URL needs to point to where our metadata volume is mounted inside the container. You can copy a file into the volume by using `docker cp` to copy it into the running container inside the `crivo-metadata` volume. The volume is mounted in the `uwsgi` container. You can check the container name by running `docker ps` and looking for the container that has the volume attached.

```python
docker cp <my_disambiguator.json> <uwsgi_container_name>:/app/crivo-metadata/
```

Another way to add your disambiguator, if you have permission, is to find the volume path on the host and place the file directly:

```python
docker volume inspect <crivo_volume_name>
```

Now you can just set the configuration variable for your disambiguator, if you have one, and rebuild the container. Like:

```python
PROBLEM_MAPPINGS_JSON_URL = "file:///app/crivo-metadata/<my_disambiguator.json>"
```

A `disambiguator.json` file will appear after you define the variables, access the problems tab for the first time and have at least a `finding` in the database.

All midnight problems will attempt to renew the disambiguator based on `PROBLEM_MAPPINGS_JSON_URL`. However, if you want to renew it immediately, you need to remove the `disambiguator.json` from `/app/crivo-metadata`.

If you also want to refresh the problems map based on the new disambiguator, you need to remove the `problems` and `id_to_problem` in redis container. Like this:

```python
docker exec -it <redis_container_name> redis-cli DEL problems id_to_problem
```

### `Vote` Database

The `Vote` database is totally separate from Dojo's PostgreSQL database.  We store analyst votes in a SQLite database that is stored in the metadata volume.  Only `file` URLs are supported:

```python
VOTE_DB_URL = "file:///app/crivo-metadata/vote-db.sqlite3"
```

> After we have data to train a prioritization model, it will be added to the metadata directory and a corresponding configuration entry will be added.

### Other Metadata

The additional metadata is also stored inside the `crivo-metadata` volume.  We currently support metadata to show the EPSS assigned to CVEs related to a vulnerability, downloaded directly from [FIRST](https://www.first.org/epss/); whether any CVE is in the [Known Exploited Vulnerabilities database](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); and a classification of impact of CVEs generated by the project using language models on the CVE description text.  These are configured with the following:

```python
# https://epss.cyentia.com/epss_scores-current.csv.gz
EPSS_DB_CSV_URL = "file:///app/crivo-metadata/epss_scores.csv.gz"
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
KEV_DB_JSON_URL = "file:///app/crivo-metadata/known_exploited_vulnerabilities.json"
CVE_CLASSIFICATION_JSON_URL = "file:///app/crivo-metadata/epss.json"
```
