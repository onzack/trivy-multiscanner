#!/bin/bash

# Copyright 2021 ONZACK AG - www.onzack.com
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


#  ______  __   _  _____      __     _____  _   __
# |  __  ||  \ | ||___  /    /  \   |  ___|| | / /
# | |  | || \ \| |   / /    / /\ \  | |    | |/ /
# | |__| || |\ | |  / /__  / ____ \ | |___ | |\ \
# |______||_| \__| /_____|/_/    \_\|_____||_| \_\
#
# Welcome to ONZACK AG - www.onzack.com

## Arguments
# $1: Path to file containing list of images to scan

## Variables
PULLERROR=false

## Script
echo '  ______  __   _  _____      __     _____  _   __'
echo ' |  __  ||  \ | ||___  /    /  \   |  ___|| | / /'
echo ' | |  | || \ \| |   / /    / /\ \  | |    | |/ /'
echo ' | |__| || |\ | |  / /__  / ____ \ | |___ | |\ \'
echo ' |______||_| \__| /_____|/_/    \_\|_____||_| \_\'
echo ""

echo "Welcome to ONZACK AG - www.onzack.com"
echo "This script scans a list of container images using Aqua Security's trivy CLI tool - https://github.com/aquasecurity/trivy"
echo ""

echo "######## List of images to scan:"
echo "$(cat $1)"

for i in $(cat $1); do
  echo ""
  echo "######## Image: $i"
  echo "----- Pull image -----"
  docker pull $i
  if [ $? == 0 ]
    then
      echo ""
      echo "----- Show age -----"
      docker image ls $i --format 'Image: {{.Repository}}:{{.Tag}} was created {{.CreatedSince}}'
      echo ""
      echo "----- Scan image -----"
      trivy image $i
    else
      PULLERROR=true
      echo ""
      echo "----- ERROR with pulling image -----"
      echo "----- -> Proceeding with next image -----"
  fi
done

if ( $PULLERROR )
  then
    echo ""
    echo "######## ATTENTION: The script was not able to pull all images! Please check the output."
fi
