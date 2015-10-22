#!/usr/bin/env bash

# preprocess using texpp
if [ ! -z "TEXPP_PATH" ]; then
    TEXPP_PATH=$HOME/segfs/repo/texpp/texpp.py
    if [ ! -e $TEXPP_PATH ]; then
	TEXPP_PATH=/segfs/linux/dance_sdk/tools/texpp.py
    fi
fi
$TEXPP_PATH main.tex main.pp.tex > main.pp.tex

# create version.tex
echo -n '\newcommand{\version}{SVN revision ' > version.tex
(svnversion -c -n || echo none) >> version.tex
echo -n '}' >> version.tex

texi2pdf main.pp.tex
mv main.pp.pdf main.pdf
