all: install

install:
		go install $(BUILD_FLAGS) ./cmd/hd
		go install $(BUILD_FLAGS) ./cmd/hcli

go.sum: go.mod
		@echo "--> Ensure dependencies have not been modified"
		GO111MODULE=on go mod verify