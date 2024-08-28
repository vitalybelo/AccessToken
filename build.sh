#!/bin/bash

export JAVA_HOME='c:/Program Files/Java/jdk-11'
export JRE_HOME='c:/Program Files/Java/jre-11.0.23.9-hotspot'

echo "$JAVA_HOME"
echo "$JRE_HOME"

function pause(){
   # shellcheck disable=SC2162
   read -p "$*"
}
mvn -Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true -Dmaven.wagon.http.ssl.ignore.validity.dates=true clean install deploy

pause 'PRESS ANY KEY'
