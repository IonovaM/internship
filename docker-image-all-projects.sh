#!/bin/sh
set -e

build_project() {
    echo "Building $1"
    cd "$1" || return
    ./gradlew clean build
    cd ..
}

projects=(
    "auth-server"
    "eureka-server"
)

# Loop through projects and build each one
for project in "${projects[@]}"
do
    build_project "$project"
done


docker build -t auth-server ./auth-server