#!/bin/bash
cd rules/enrich/
./index_gen.sh
cd ../../
cd rules/detection
./index_gen.sh
