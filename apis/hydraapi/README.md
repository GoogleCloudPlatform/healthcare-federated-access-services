# Generate models for hydraapi

## Install go-swagger

```
git clone https://github.com/go-swagger/go-swagger
cd go-swagger
go install ./cmd/swagger
```

[Other installations](https://goswagger.io/install.html)

## Generate files

`swagger generate client --spec=https://raw.githubusercontent.com/ory/hydra/master/docs/api.swagger.json --skip-operations --skip-validation --model-package=apis/hydraapi`

## Edit files

Remove validation functions.
