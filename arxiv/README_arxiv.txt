Compile order:
  pdflatex paper_cose.tex
  bibtex paper_cose
  pdflatex paper_cose.tex
  pdflatex paper_cose.tex

Notes:
- Source bundle includes data/*.csv used by pgfplots.
- elsarticle.cls and elsarticle-harv.bst are included for robustness.
