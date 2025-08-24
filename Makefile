IMAGE ?= sentra-scanner:local

.PHONY: build run shell push clean

build:
	docker build -t $(IMAGE) .

run:
	docker run --rm -it --env-file ./.env $(IMAGE)

shell:
	docker run --rm -it --entrypoint /bin/bash --env-file ./.env $(IMAGE)

tag:
	@if [ -z "$$TAG" ]; then echo "Set TAG=vX.Y.Z" && exit 1; fi;     	docker tag $(IMAGE) $(IMAGE):$$TAG

push:
	@if [ -z "$$REPO" ]; then echo "Set REPO=your-ecr-or-dockerhub-repo" && exit 1; fi;     	docker tag $(IMAGE) $(REPO) && docker push $(REPO)

clean:
	docker image prune -f
