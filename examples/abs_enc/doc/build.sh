#!/usr/bin/env sh

# preprocess
../../../texpp.py main.tex main.pp.tex > main.pp.tex

# create version.tex
echo -n '\\newcommand{\\version}{' > version.tex
(svnversion -c -n || echo none) >> version.tex
echo -n '}' >> version.tex

texi2pdf main.pp.tex
mv main.pp.pdf main.pdf
