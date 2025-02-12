VENDOR=Spirent
NAME=vstc
IMAGE_FORMAT=qcow2
IMAGE_GLOB=*.qcow2

VERSION=$(shell echo $(IMAGE) | sed -e 's/.\+[^0-9]\([0-9]\+\.[0-9]\+\.[0-9]\+[sb]\?\?\)\([^0-9].*\|$$\)/\1/')

-include ../makefile-sanity.include
-include ../makefile.include

docker-pre-build:
	-cat cidfile | xargs --no-run-if-empty docker rm -f
	-rm cidfile

docker-build: docker-build-common
	docker run --cidfile cidfile --privileged $(REGISTRY)$(VENDOR)_$(NAME):$(VERSION) --trace --install
	docker commit --change='ENTRYPOINT ["/launch.py"]' $$(cat cidfile) $(REGISTRY)$(VENDOR)_$(NAME):$(VERSION)
	docker rm -f $$(cat cidfile)
