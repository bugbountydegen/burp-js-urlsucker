# Makefile - simple javac -> jar build
SRC_DIR := src/main/java
OUT_DIR := out
PKG := com/defensahacker/burpsuite
MAIN_CLASS := com.defensahacker.burpsuite.BurpUrlSucker
MONTOYA_JAR ?= montoya-api-2025.8.jar
JAR_OUT ?= js-urlsucker-montoya.jar

SRCS := $(shell find $(SRC_DIR) -name "*.java")
CLASSES := $(patsubst $(SRC_DIR)/%.java, $(OUT_DIR)/%.class, $(SRCS))

all: $(JAR_OUT)

$(OUT_DIR)/%.class: $(SRC_DIR)/%.java
	@mkdir -p $(dir $@)
	javac -cp "$(MONTOYA_JAR)" -d $(OUT_DIR) $<

$(JAR_OUT): $(CLASSES)
	@mkdir -p dist
	cd $(OUT_DIR) && jar cf ../dist/$(JAR_OUT) .
	@echo "Built dist/$(JAR_OUT)"

clean:
	rm -rf $(OUT_DIR) dist

.PHONY: all clean

