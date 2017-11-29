# Copyright 2017 Nike Inc.

# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION ?= $(shell git describe --always --tags)
BUILD_CMD = go build -o build/harbormaster-$(VERSION)-$${GOOS}-$${GOARCH} &
IMAGE_REPO = nikeoss

default:
	$(MAKE) bootstrap
	$(MAKE) build

test:
	go vet ./...
	golint -set_exit_status $(shell go list ./... | grep -v vendor)
	go test -covermode=atomic -race -v ./...
bootstrap:
	dep ensure
	touch bootstrap
build:
	go build -o harbormaster
clean:
	rm -rf build
	rm -f release image bootstrap
release: bootstrap
	@echo "Running cross-compile jobs in parallel..."
	bash -c '\
		export GOOS=darwin;  export GOARCH=amd64; $(BUILD_CMD) \
		export GOOS=linux;   export GOARCH=amd64; $(BUILD_CMD) \
		export GOOS=windows; export GOARCH=amd64; $(BUILD_CMD) \
		wait \
	'
	touch release

image: release
	@echo "Wrapping binary in Docker container"
	docker build -t $(IMAGE_REPO)/harbormaster:$(VERSION) .
	touch image

image-push: image
	docker push $(IMAGE_REPO)/harbormaster:$(VERSION)

.PHONY: test build clean image-push

