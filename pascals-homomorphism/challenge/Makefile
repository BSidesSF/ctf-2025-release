BUILD?=$(shell basename `pwd`)-build

all:
	docker buildx build . --platform linux/amd64 --progress=plain -t ${BUILD} -f Dockerfile.build
	docker run --platform linux/amd64 --privileged --rm -v ${PWD}:/src --env UID=$(shell id -u) --env GID=$(shell id -g) -ti ${BUILD}

clean:
	cd src && make clean

# This runs inside Docker, customize this part!
indocker:
	cd src && make
	chown -R $(UID):$(GID) src/
