
To build the Docker image locally:
```shell
$ docker build -f deploy/build/${BINNAME?}/Dockerfile -t gcr.io/${PROJECT?}/hcls-fa-${BINNAME?} .
```

To build the Docker image using Cloud Build:

```shell
$ gcloud builds submit --config deploy/build/${BINNAME?}/cloudbuild.yaml .
```
To test the Docker image locally you can run:

```shell
$ docker run -p 0.0.0.0:8080:8080 gcr.io/${PROJECT?}/hcls-fa-${BINNAME?}
```
To deply to GAE Flex:

```shell
$ gcloud beta -q app deploy deploy/build/${BINNAME?}/${BINNAME?}.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-${BINNAME?}:latest
```
